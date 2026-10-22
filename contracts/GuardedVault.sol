// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title GuardedVault — on-chain version of the Kestrel "Honey-Vault" brakes.
/// @notice Large or unusual withdrawals are queued behind a time-lock, need m-of-n guardian
///         approvals above a threshold, can be vetoed by any single guardian, and the owner
///         can cancel during the window. Loosening any protection is itself time-locked.
/// @dev    HACKATHON CODE: not audited. The duress-PIN decoy is deliberately NOT implemented
///         on-chain. Every transaction is public, so an attacker watching the chain would
///         spot a "duress" call. Duress belongs in the custodial / bank layer (see server/vault.js).
contract GuardedVault {
    struct Settings {
        uint256 instantLimit;     // withdrawals <= this execute immediately
        uint256 guardianLimit;    // withdrawals >= this need `guardiansRequired` approvals
        uint64  delay;            // base time-lock for queued withdrawals (seconds)
        uint64  settingsDelay;    // time-lock for LOOSENING settings (seconds)
        uint8   guardiansRequired;
    }

    struct Withdrawal {
        address payable to;
        uint256 amount;
        uint64  releaseAt;
        uint8   approvals;
        bool    needsGuardians;
        bool    done;             // executed, cancelled or vetoed
    }

    struct PendingSettings {
        Settings next;
        uint64   effectiveAt;
        bool     active;
    }

    address public immutable owner;
    mapping(address => bool) public isGuardian;
    uint8 public guardianCount;
    bool public frozen;

    Settings public settings;
    PendingSettings public pendingSettings;
    Withdrawal[] public withdrawals;
    mapping(uint256 => mapping(address => bool)) public approved;
    mapping(address => uint64) public firstPaidAt; // new-payee detection
    uint64 public constant NEW_PAYEE_PERIOD = 1 days;
    uint256 public reserved; // funds held by queued withdrawals

    event Queued(uint256 indexed id, address indexed to, uint256 amount, uint64 releaseAt, bool needsGuardians);
    event Executed(uint256 indexed id);
    event Cancelled(uint256 indexed id);
    event Vetoed(uint256 indexed id, address indexed guardian);
    event Approved(uint256 indexed id, address indexed guardian);
    event Frozen(address indexed by, bool frozen);
    event SettingsProposed(Settings next, uint64 effectiveAt);
    event SettingsApplied(Settings next);

    error NotOwner();
    error NotGuardian();
    error IsFrozen();
    error BadState();
    error TooEarly();
    error Insufficient();

    modifier onlyOwner() { if (msg.sender != owner) revert NotOwner(); _; }
    modifier onlyGuardian() { if (!isGuardian[msg.sender]) revert NotGuardian(); _; }

    constructor(address[] memory guardians, Settings memory initial) payable {
        owner = msg.sender;
        for (uint256 i = 0; i < guardians.length; i++) {
            if (!isGuardian[guardians[i]] && guardians[i] != msg.sender) {
                isGuardian[guardians[i]] = true;
                guardianCount++;
            }
        }
        require(initial.guardiansRequired >= 1 && initial.guardiansRequired <= guardianCount, "bad m-of-n");
        settings = initial;
    }

    receive() external payable {}

    function available() public view returns (uint256) { return address(this).balance - reserved; }

    /// Small payments to known payees go through instantly; everything else is queued.
    function withdraw(address payable to, uint256 amount) external onlyOwner returns (uint256 id) {
        if (frozen) revert IsFrozen();
        if (amount > available()) revert Insufficient();
        bool newPayee = firstPaidAt[to] == 0 || block.timestamp - firstPaidAt[to] < NEW_PAYEE_PERIOD;
        if (firstPaidAt[to] == 0) firstPaidAt[to] = uint64(block.timestamp);

        if (amount <= settings.instantLimit && !newPayee) {
            withdrawals.push(Withdrawal(to, amount, uint64(block.timestamp), 0, false, true));
            id = withdrawals.length - 1;
            (bool ok, ) = to.call{value: amount}("");
            require(ok, "transfer failed");
            emit Executed(id);
            return id;
        }

        bool needsGuardians = amount >= settings.guardianLimit;
        // risk-scaled delay: new payees and guardian-level amounts wait longer
        uint64 delay = settings.delay * (1 + (newPayee ? 1 : 0) + (needsGuardians ? 2 : 0));
        uint64 releaseAt = uint64(block.timestamp) + delay;
        withdrawals.push(Withdrawal(to, amount, releaseAt, 0, needsGuardians, false));
        id = withdrawals.length - 1;
        reserved += amount;
        emit Queued(id, to, amount, releaseAt, needsGuardians);
    }

    function approve(uint256 id) external onlyGuardian {
        Withdrawal storage w = withdrawals[id];
        if (w.done || approved[id][msg.sender]) revert BadState();
        approved[id][msg.sender] = true;
        w.approvals++;
        emit Approved(id, msg.sender);
    }

    /// Any single guardian can stop a queued withdrawal.
    function veto(uint256 id) external onlyGuardian {
        Withdrawal storage w = withdrawals[id];
        if (w.done) revert BadState();
        w.done = true;
        reserved -= w.amount;
        emit Vetoed(id, msg.sender);
    }

    function cancel(uint256 id) external onlyOwner {
        Withdrawal storage w = withdrawals[id];
        if (w.done) revert BadState();
        w.done = true;
        reserved -= w.amount;
        emit Cancelled(id);
    }

    /// Anyone may trigger execution once the conditions hold (keeps the owner's key cold).
    function execute(uint256 id) external {
        if (frozen) revert IsFrozen();
        Withdrawal storage w = withdrawals[id];
        if (w.done) revert BadState();
        if (block.timestamp < w.releaseAt) revert TooEarly();
        if (w.needsGuardians && w.approvals < settings.guardiansRequired) revert BadState();
        w.done = true;
        reserved -= w.amount;
        (bool ok, ) = w.to.call{value: w.amount}("");
        require(ok, "transfer failed");
        emit Executed(id);
    }

    /// Owner or any guardian can freeze. Only a guardian can unfreeze,
    /// so a thief holding the owner key can't undo a panic freeze.
    function freeze() external {
        if (msg.sender != owner && !isGuardian[msg.sender]) revert NotGuardian();
        frozen = true;
        emit Frozen(msg.sender, true);
    }

    function unfreeze() external onlyGuardian {
        frozen = false;
        emit Frozen(msg.sender, false);
    }

    /// Tightening applies now; loosening waits `settingsDelay` and is vetoable.
    function proposeSettings(Settings calldata next) external onlyOwner {
        require(next.guardiansRequired >= 1 && next.guardiansRequired <= guardianCount, "bad m-of-n");
        Settings memory cur = settings;
        bool tighter = next.instantLimit <= cur.instantLimit && next.guardianLimit <= cur.guardianLimit
            && next.delay >= cur.delay && next.settingsDelay >= cur.settingsDelay && next.guardiansRequired >= cur.guardiansRequired;
        if (tighter) {
            settings = next;
            delete pendingSettings;
            emit SettingsApplied(next);
        } else {
            uint64 at = uint64(block.timestamp) + cur.settingsDelay;
            pendingSettings = PendingSettings(next, at, true);
            emit SettingsProposed(next, at);
        }
    }

    function applySettings() external {
        PendingSettings memory p = pendingSettings;
        if (!p.active) revert BadState();
        if (block.timestamp < p.effectiveAt) revert TooEarly();
        settings = p.next;
        delete pendingSettings;
        emit SettingsApplied(p.next);
    }

    function vetoSettings() external onlyGuardian {
        delete pendingSettings;
    }
}
