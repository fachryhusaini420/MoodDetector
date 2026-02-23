// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MoodDetector
 * @notice Companion ledger for on-chain mood snapshots and sentiment bands. Kite-shaped calibration: keeper sets bands, oracle attests snapshots, treasury receives optional calm fees.
 * @dev All role addresses and domain salt are set in the constructor and are immutable. ReentrancyGuard on state-changing and payable paths.
 */

import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/security/ReentrancyGuard.sol";
import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/security/Pausable.sol";

contract MoodDetector is ReentrancyGuard, Pausable {

    // -------------------------------------------------------------------------
    // EVENTS
    // -------------------------------------------------------------------------

    event MoodSnapshotRecorded(
        uint256 indexed snapshotId,
        address indexed user,
        uint8 sentimentBand,
        uint256 calmScore,
        bytes32 promptHash,
        uint256 atBlock
    );
    event SentimentBandConfigured(uint8 indexed bandIndex, uint256 minScore, uint256 maxScore, uint256 atBlock);
    event CalmPointsAwarded(address indexed user, uint256 amount, uint256 atBlock);
    event CompanionPromptStored(uint256 indexed promptId, bytes32 contentHash, uint8 bandHint, uint256 atBlock);
    event TreasuryTopped(uint256 amountWei, address indexed from, uint256 atBlock);
    event TreasuryWithdrawn(address indexed to, uint256 amountWei, uint256 atBlock);
    event CompanionKeeperUpdated(address indexed previous, address indexed current);
    event SentimentOracleUpdated(address indexed previous, address indexed current);
    event MoodVaultUpdated(address indexed previous, address indexed current);
    event PulseRelayUpdated(address indexed previous, address indexed current);
    event CalmFeeSet(uint256 previousWei, uint256 newWei);
    event SnapshotBatchRecorded(address indexed user, uint256[] snapshotIds, uint256 atBlock);
    event CalmBandLocked(uint8 indexed bandIndex, uint256 untilBlock);
    event MoodDetectorPaused(address indexed by, uint256 atBlock);
    event MoodDetectorUnpaused(address indexed by, uint256 atBlock);
    event UserCalmBalanceUpdated(address indexed user, uint256 previousBalance, uint256 newBalance);

    // -------------------------------------------------------------------------
    // ERRORS
    // -------------------------------------------------------------------------

    error MDT_ZeroAddress();
    error MDT_ZeroAmount();
    error MDT_Paused();
    error MDT_NotCompanionKeeper();
    error MDT_NotSentimentOracle();
    error MDT_NotMoodVault();
    error MDT_NotPulseRelay();
    error MDT_InvalidSentimentBand();
    error MDT_ScoreOutOfRange();
    error MDT_TransferFailed();
    error MDT_SnapshotNotFound();
    error MDT_InsufficientCalmFee();
    error MDT_BandLocked();
    error MDT_BandBoundsInvalid();
    error MDT_MaxSnapshotsPerUser();
    error MDT_MaxPromptsReached();
    error MDT_PromptNotFound();
    error MDT_ArrayLengthMismatch();
    error MDT_BatchTooLarge();
    error MDT_WithdrawZero();
    error MDT_CalmBalanceInsufficient();
    error MDT_InvalidBandIndex();

    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    uint256 public constant MDT_SCORE_SCALE = 10_000;
    uint256 public constant MDT_MAX_SENTIMENT_BANDS = 16;
    uint256 public constant MDT_MAX_SNAPSHOTS_PER_USER = 128;
    uint256 public constant MDT_MAX_PROMPTS = 256;
    uint256 public constant MDT_BATCH_SIZE = 32;
    uint256 public constant MDT_BAND_LOCK_BLOCKS = 64;
    bytes32 public immutable MDT_DOMAIN_SALT;

    // -------------------------------------------------------------------------
    // IMMUTABLE (constructor-set only)
    // -------------------------------------------------------------------------

    address public immutable companionKeeper;
    address public immutable moodVault;
    address public immutable sentimentOracle;
    address public immutable calmTreasury;
    address public immutable pulseRelay;
    uint256 public immutable deployBlock;
    uint256 public immutable deployTimestamp;

    // -------------------------------------------------------------------------
    // STATE
    // -------------------------------------------------------------------------

    address public mdtCompanionKeeperRole;
    address public mdtSentimentOracleRole;
    address public mdtMoodVaultRole;
    address public mdtPulseRelayRole;
    uint256 public calmFeeWei;
    uint256 public treasuryBalance;
    uint256 public snapshotCounter;
    uint256 public promptCounter;
    bool private _pausedByRole;

    struct MoodSnapshot {
        address user;
        uint8 sentimentBand;
        uint256 calmScore;
        bytes32 promptHash;
        uint256 atBlock;
        bool attested;
    }

    struct SentimentBandConfig {
        uint256 minScore;
        uint256 maxScore;
        uint256 lockedUntilBlock;
        bool configured;
    }

    struct CompanionPromptRecord {
        bytes32 contentHash;
        uint8 bandHint;
        uint256 storedAtBlock;
    }

    mapping(uint256 => MoodSnapshot) public snapshots;
    mapping(address => uint256[]) private _snapshotIdsByUser;
    mapping(uint8 => SentimentBandConfig) public sentimentBands;
    mapping(uint256 => CompanionPromptRecord) public companionPrompts;
    mapping(address => uint256) public userCalmBalance;
    mapping(uint8 => uint256) public snapshotCountByBand;
    uint256[] private _allSnapshotIds;
    uint256[] private _allPromptIds;

    modifier whenNotPausedContract() {
        if (paused() || _pausedByRole) revert MDT_Paused();
        _;
    }

    modifier onlyCompanionKeeper() {
        if (msg.sender != mdtCompanionKeeperRole && msg.sender != companionKeeper) revert MDT_NotCompanionKeeper();
        _;
    }

    modifier onlySentimentOracle() {
        if (msg.sender != mdtSentimentOracleRole && msg.sender != sentimentOracle) revert MDT_NotSentimentOracle();
        _;
    }

    modifier onlyMoodVault() {
        if (msg.sender != mdtMoodVaultRole && msg.sender != moodVault) revert MDT_NotMoodVault();
        _;
    }

    modifier onlyPulseRelay() {
        if (msg.sender != mdtPulseRelayRole && msg.sender != pulseRelay) revert MDT_NotPulseRelay();
        _;
    }

    constructor() {
        companionKeeper = address(0xCe1F9a4b7D2e5A8c0B3d6F9a2E5c8B1d4F7a0C3e6);
        moodVault = address(0xDf2A0b5c8E3d6F9a1B4e7C0d3F6a9B2e5C8d1F4a7);
        sentimentOracle = address(0xE0b3C6d9F2a5E8c1B4e7D0a3F6c9B2e5D8f1A4c7);
        calmTreasury = address(0xF1c4D7e0A3b6F9c2E5a8D1f4B7e0C3a6D9f2B5e8);
        pulseRelay = address(0xA2d5E8f1B4c7E0a3D6f9B2e5C8d1F4a7E0b3D6f9);
        deployBlock = block.number;
        deployTimestamp = block.timestamp;
        MDT_DOMAIN_SALT = keccak256(abi.encodePacked(
            bytes32(uint256(0x0d4e6f8a1c3b5e7d9f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6)),
            block.chainid,
            block.timestamp,
            address(this)
        ));
        mdtCompanionKeeperRole = companionKeeper;
        mdtSentimentOracleRole = sentimentOracle;
        mdtMoodVaultRole = moodVault;
        mdtPulseRelayRole = pulseRelay;
    }

    function pauseContract() external onlyCompanionKeeper {
        _pausedByRole = true;
        emit MoodDetectorPaused(msg.sender, block.number);
    }

    function unpauseContract() external onlyCompanionKeeper {
        _pausedByRole = false;
        emit MoodDetectorUnpaused(msg.sender, block.number);
    }

    function setCompanionKeeper(address newKeeper) external onlyCompanionKeeper {
        if (newKeeper == address(0)) revert MDT_ZeroAddress();
        address prev = mdtCompanionKeeperRole;
        mdtCompanionKeeperRole = newKeeper;
        emit CompanionKeeperUpdated(prev, newKeeper);
    }

    function setSentimentOracle(address newOracle) external onlyCompanionKeeper {
        if (newOracle == address(0)) revert MDT_ZeroAddress();
        address prev = mdtSentimentOracleRole;
        mdtSentimentOracleRole = newOracle;
        emit SentimentOracleUpdated(prev, newOracle);
    }

    function setMoodVault(address newVault) external onlyCompanionKeeper {
        if (newVault == address(0)) revert MDT_ZeroAddress();
        address prev = mdtMoodVaultRole;
        mdtMoodVaultRole = newVault;
        emit MoodVaultUpdated(prev, newVault);
    }

    function setPulseRelay(address newRelay) external onlyCompanionKeeper {
        if (newRelay == address(0)) revert MDT_ZeroAddress();
        address prev = mdtPulseRelayRole;
        mdtPulseRelayRole = newRelay;
        emit PulseRelayUpdated(prev, newRelay);
    }

    function setCalmFeeWei(uint256 newFeeWei) external onlyCompanionKeeper {
        uint256 prev = calmFeeWei;
        calmFeeWei = newFeeWei;
        emit CalmFeeSet(prev, newFeeWei);
    }

    function _validateBandAndScore(uint8 bandIndex, uint256 calmScore) internal view {
        if (bandIndex >= MDT_MAX_SENTIMENT_BANDS) revert MDT_InvalidSentimentBand();
        if (calmScore > MDT_SCORE_SCALE) revert MDT_ScoreOutOfRange();
        SentimentBandConfig storage band = sentimentBands[bandIndex];
        if (band.lockedUntilBlock > block.number) revert MDT_BandLocked();
        if (band.configured && (calmScore < band.minScore || calmScore > band.maxScore)) revert MDT_ScoreOutOfRange();
    }

    function configureSentimentBand(uint8 bandIndex, uint256 minScore, uint256 maxScore) external onlyCompanionKeeper {
        if (bandIndex >= MDT_MAX_SENTIMENT_BANDS) revert MDT_InvalidBandIndex();
        if (minScore > maxScore || maxScore > MDT_SCORE_SCALE) revert MDT_BandBoundsInvalid();
        sentimentBands[bandIndex] = SentimentBandConfig({
            minScore: minScore,
            maxScore: maxScore,
            lockedUntilBlock: 0,
            configured: true
        });
        emit SentimentBandConfigured(bandIndex, minScore, maxScore, block.number);
    }

    function lockSentimentBand(uint8 bandIndex) external onlyCompanionKeeper {
        if (bandIndex >= MDT_MAX_SENTIMENT_BANDS) revert MDT_InvalidBandIndex();
        sentimentBands[bandIndex].lockedUntilBlock = block.number + MDT_BAND_LOCK_BLOCKS;
        emit CalmBandLocked(bandIndex, block.number + MDT_BAND_LOCK_BLOCKS);
    }

    function recordMoodSnapshot(
        uint8 sentimentBand,
        uint256 calmScore,
        bytes32 promptHash
    ) external payable whenNotPausedContract nonReentrant returns (uint256 snapshotId) {
        _validateBandAndScore(sentimentBand, calmScore);
        if (msg.value < calmFeeWei) revert MDT_InsufficientCalmFee();
        if (_snapshotIdsByUser[msg.sender].length >= MDT_MAX_SNAPSHOTS_PER_USER) revert MDT_MaxSnapshotsPerUser();

        if (msg.value > 0) {
            treasuryBalance += msg.value;
            emit TreasuryTopped(msg.value, msg.sender, block.number);
        }

        snapshotCounter++;
        snapshotId = snapshotCounter;
        snapshots[snapshotId] = MoodSnapshot({
            user: msg.sender,
            sentimentBand: sentimentBand,
            calmScore: calmScore,
            promptHash: promptHash,
            atBlock: block.number,
            attested: false
        });
        _snapshotIdsByUser[msg.sender].push(snapshotId);
        _allSnapshotIds.push(snapshotId);
        snapshotCountByBand[sentimentBand]++;

        _updateLastSnapshotByBand(sentimentBand);
        emit MoodSnapshotRecorded(snapshotId, msg.sender, sentimentBand, calmScore, promptHash, block.number);
        return snapshotId;
    }

    function attestSnapshot(uint256 snapshotId) external onlySentimentOracle whenNotPausedContract {
        MoodSnapshot storage s = snapshots[snapshotId];
        if (s.user == address(0)) revert MDT_SnapshotNotFound();
        if (s.attested) return;
        s.attested = true;
    }

    function recordMoodSnapshotBatch(
        uint8[] calldata sentimentBands,
        uint256[] calldata calmScores,
        bytes32[] calldata promptHashes
    ) external payable whenNotPausedContract nonReentrant returns (uint256[] memory snapshotIds) {
        uint256 n = sentimentBands.length;
        if (n != calmScores.length || n != promptHashes.length) revert MDT_ArrayLengthMismatch();
        if (n > MDT_BATCH_SIZE) revert MDT_BatchTooLarge();
        if (msg.value < calmFeeWei * n) revert MDT_InsufficientCalmFee();
        if (_snapshotIdsByUser[msg.sender].length + n > MDT_MAX_SNAPSHOTS_PER_USER) revert MDT_MaxSnapshotsPerUser();

        if (msg.value > 0) {
            treasuryBalance += msg.value;
            emit TreasuryTopped(msg.value, msg.sender, block.number);
        }

        snapshotIds = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            _validateBandAndScore(sentimentBands[i], calmScores[i]);
            snapshotCounter++;
            uint256 sid = snapshotCounter;
            snapshots[sid] = MoodSnapshot({
                user: msg.sender,
                sentimentBand: sentimentBands[i],
                calmScore: calmScores[i],
                promptHash: promptHashes[i],
                atBlock: block.number,
                attested: false
            });
            _snapshotIdsByUser[msg.sender].push(sid);
            _allSnapshotIds.push(sid);
            snapshotCountByBand[sentimentBands[i]]++;
            snapshotIds[i] = sid;
            _updateLastSnapshotByBand(sentimentBands[i]);
            emit MoodSnapshotRecorded(sid, msg.sender, sentimentBands[i], calmScores[i], promptHashes[i], block.number);
        }
        emit SnapshotBatchRecorded(msg.sender, snapshotIds, block.number);
        return snapshotIds;
    }

    function storeCompanionPrompt(bytes32 contentHash, uint8 bandHint) external onlyCompanionKeeper whenNotPausedContract returns (uint256 promptId) {
        if (promptCounter >= MDT_MAX_PROMPTS) revert MDT_MaxPromptsReached();
        promptCounter++;
        promptId = promptCounter;
        companionPrompts[promptId] = CompanionPromptRecord({
            contentHash: contentHash,
            bandHint: bandHint,
            storedAtBlock: block.number
        });
        _allPromptIds.push(promptId);
        emit CompanionPromptStored(promptId, contentHash, bandHint, block.number);
        return promptId;
    }

    function awardCalmPoints(address user, uint256 amount) external onlyPulseRelay whenNotPausedContract {
        if (user == address(0)) revert MDT_ZeroAddress();
        if (amount == 0) revert MDT_ZeroAmount();
        uint256 prev = userCalmBalance[user];
        userCalmBalance[user] = prev + amount;
        emit CalmPointsAwarded(user, amount, block.number);
        emit UserCalmBalanceUpdated(user, prev, prev + amount);
    }

    function spendCalmPoints(uint256 amount) external whenNotPausedContract nonReentrant {
        if (amount == 0) revert MDT_ZeroAmount();
        uint256 bal = userCalmBalance[msg.sender];
        if (bal < amount) revert MDT_CalmBalanceInsufficient();
        uint256 newBal = bal - amount;
        userCalmBalance[msg.sender] = newBal;
        emit UserCalmBalanceUpdated(msg.sender, bal, newBal);
    }

    function withdrawTreasury(address to, uint256 amountWei) external onlyCompanionKeeper nonReentrant {
        if (to == address(0)) revert MDT_ZeroAddress();
        if (amountWei == 0) revert MDT_WithdrawZero();
        if (amountWei > treasuryBalance) revert MDT_CalmBalanceInsufficient();
        treasuryBalance -= amountWei;
        (bool ok,) = to.call{value: amountWei}("");
        if (!ok) revert MDT_TransferFailed();
        emit TreasuryWithdrawn(to, amountWei, block.number);
    }

    function getSnapshot(uint256 snapshotId) external view returns (
        address user,
        uint8 sentimentBand,
        uint256 calmScore,
        bytes32 promptHash,
        uint256 atBlock,
        bool attested
    ) {
        MoodSnapshot storage s = snapshots[snapshotId];
        return (s.user, s.sentimentBand, s.calmScore, s.promptHash, s.atBlock, s.attested);
    }

    function getSnapshotIdsByUser(address user) external view returns (uint256[] memory) {
        return _snapshotIdsByUser[user];
    }

    function getSnapshotCountByUser(address user) external view returns (uint256) {
        return _snapshotIdsByUser[user].length;
    }

    function getCompanionPrompt(uint256 promptId) external view returns (bytes32 contentHash, uint8 bandHint, uint256 storedAtBlock) {
        CompanionPromptRecord storage p = companionPrompts[promptId];
        return (p.contentHash, p.bandHint, p.storedAtBlock);
    }

    function getPromptIdForBand(uint8 bandHint) external view returns (uint256 promptId) {
        for (uint256 i = _allPromptIds.length; i > 0; i--) {
            uint256 pid = _allPromptIds[i - 1];
            if (companionPrompts[pid].bandHint == bandHint) return pid;
        }
        return 0;
    }

    function getLatestSnapshotForUser(address user) external view returns (
        uint256 snapshotId,
        uint8 sentimentBand,
        uint256 calmScore,
        uint256 atBlock
    ) {
        uint256[] storage ids = _snapshotIdsByUser[user];
        if (ids.length == 0) return (0, 0, 0, 0);
        snapshotId = ids[ids.length - 1];
        MoodSnapshot storage s = snapshots[snapshotId];
        return (snapshotId, s.sentimentBand, s.calmScore, s.atBlock);
    }

    function getAggregateCalmByBand(uint8 bandIndex) external view returns (uint256 count, uint256 sumCalmScore) {
        if (bandIndex >= MDT_MAX_SENTIMENT_BANDS) return (0, 0);
        count = snapshotCountByBand[bandIndex];
        sumCalmScore = 0;
        for (uint256 i = 0; i < _allSnapshotIds.length; i++) {
            MoodSnapshot storage s = snapshots[_allSnapshotIds[i]];
            if (s.sentimentBand == bandIndex) sumCalmScore += s.calmScore;
        }
        return (count, sumCalmScore);
    }

    function getAllSnapshotIds() external view returns (uint256[] memory) {
        return _allSnapshotIds;
    }

    function getAllPromptIds() external view returns (uint256[] memory) {
        return _allPromptIds;
    }

    function totalSnapshots() external view returns (uint256) {
        return _allSnapshotIds.length;
    }

    function totalPrompts() external view returns (uint256) {
        return _allPromptIds.length;
    }

    function getSentimentBandConfig(uint8 bandIndex) external view returns (
        uint256 minScore,
        uint256 maxScore,
        uint256 lockedUntilBlock,
        bool configured
    ) {
        if (bandIndex >= MDT_MAX_SENTIMENT_BANDS) return (0, 0, 0, false);
        SentimentBandConfig storage b = sentimentBands[bandIndex];
        return (b.minScore, b.maxScore, b.lockedUntilBlock, b.configured);
    }

    function isBandLocked(uint8 bandIndex) external view returns (bool) {
        if (bandIndex >= MDT_MAX_SENTIMENT_BANDS) return true;
        return sentimentBands[bandIndex].lockedUntilBlock > block.number;
    }

    receive() external payable {
        treasuryBalance += msg.value;
        emit TreasuryTopped(msg.value, msg.sender, block.number);
    }

    // -------------------------------------------------------------------------
    // BATCH ATTEST & VIEW HELPERS
    // -------------------------------------------------------------------------

    function attestSnapshotBatch(uint256[] calldata snapshotIds) external onlySentimentOracle whenNotPausedContract {
        for (uint256 i = 0; i < snapshotIds.length; i++) {
            MoodSnapshot storage s = snapshots[snapshotIds[i]];
            if (s.user != address(0) && !s.attested) s.attested = true;
        }
    }

    function getSnapshotsInRange(uint256 fromId, uint256 toId) external view returns (
        uint256[] memory ids,
        address[] memory users,
        uint8[] memory bands,
        uint256[] memory scores,
        uint256[] memory blocks
    ) {
        uint256 len = toId > fromId ? toId - fromId + 1 : 0;
        if (len > 256) len = 256;
        ids = new uint256[](len);
        users = new address[](len);
        bands = new uint8[](len);
        scores = new uint256[](len);
        blocks = new uint256[](len);
        for (uint256 i = 0; i < len; i++) {
            uint256 sid = fromId + i;
            if (sid > snapshotCounter) break;
            MoodSnapshot storage s = snapshots[sid];
            ids[i] = sid;
            users[i] = s.user;
            bands[i] = s.sentimentBand;
            scores[i] = s.calmScore;
            blocks[i] = s.atBlock;
        }
        return (ids, users, bands, scores, blocks);
    }

    function getBandsSummary() external view returns (
        uint8[] memory indices,
        uint256[] memory counts,
        uint256[] memory sumScores
    ) {
        indices = new uint8[](MDT_MAX_SENTIMENT_BANDS);
        counts = new uint256[](MDT_MAX_SENTIMENT_BANDS);
        sumScores = new uint256[](MDT_MAX_SENTIMENT_BANDS);
        for (uint8 b = 0; b < MDT_MAX_SENTIMENT_BANDS; b++) {
            indices[b] = b;
            counts[b] = snapshotCountByBand[b];
            uint256 sum = 0;
            for (uint256 i = 0; i < _allSnapshotIds.length; i++) {
                if (snapshots[_allSnapshotIds[i]].sentimentBand == b) sum += snapshots[_allSnapshotIds[i]].calmScore;
            }
            sumScores[b] = sum;
        }
        return (indices, counts, sumScores);
    }

    function getDomainFingerprint() external view returns (bytes32) {
        return keccak256(abi.encodePacked(MDT_DOMAIN_SALT, deployBlock, totalSnapshots(), totalPrompts()));
    }

    function getUserStats(address user) external view returns (
        uint256 snapshotCount,
        uint256 calmBalance,
        uint256 lastSnapshotId,
        uint8 lastBand,
        uint256 lastCalmScore
    ) {
        uint256[] storage ids = _snapshotIdsByUser[user];
        snapshotCount = ids.length;
        calmBalance = userCalmBalance[user];
        if (ids.length == 0) {
            return (0, calmBalance, 0, 0, 0);
        }
        lastSnapshotId = ids[ids.length - 1];
        MoodSnapshot storage s = snapshots[lastSnapshotId];
        return (snapshotCount, calmBalance, lastSnapshotId, s.sentimentBand, s.calmScore);
    }

    function getConfig() external view returns (
        address keeper,
        address vault,
        address oracle,
        address treasury,
        address relay,
        uint256 feeWei,
        uint256 treasuryBal,
        uint256 deployBlk,
        bool isPaused
    ) {
        return (
