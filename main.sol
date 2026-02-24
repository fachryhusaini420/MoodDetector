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
            mdtCompanionKeeperRole,
            mdtMoodVaultRole,
            mdtSentimentOracleRole,
            calmTreasury,
            mdtPulseRelayRole,
            calmFeeWei,
            treasuryBalance,
            deployBlock,
            paused() || _pausedByRole
        );
    }

    // -------------------------------------------------------------------------
    // EPOCH / WINDOW HELPERS (block-based windows for analytics)
    // -------------------------------------------------------------------------

    uint256 public constant MDT_EPOCH_BLOCKS = 6400;

    function getCurrentEpochIndex() external view returns (uint256) {
        if (block.number <= deployBlock) return 0;
        return (block.number - deployBlock) / MDT_EPOCH_BLOCKS;
    }

    function getSnapshotIdsInEpoch(uint256 epochIndex) external view returns (uint256[] memory) {
        uint256 startBlock = deployBlock + epochIndex * MDT_EPOCH_BLOCKS;
        uint256 endBlock = startBlock + MDT_EPOCH_BLOCKS;
        uint256[] memory temp = new uint256[](_allSnapshotIds.length);
        uint256 count = 0;
        for (uint256 i = 0; i < _allSnapshotIds.length; i++) {
            MoodSnapshot storage s = snapshots[_allSnapshotIds[i]];
            if (s.atBlock >= startBlock && s.atBlock < endBlock) {
                temp[count] = _allSnapshotIds[i];
                count++;
            }
        }
        uint256[] memory out = new uint256[](count);
        for (uint256 j = 0; j < count; j++) out[j] = temp[j];
        return out;
    }

    function getEpochStats(uint256 epochIndex) external view returns (
        uint256 snapshotCount,
        uint256 totalCalmScore,
        uint256 attestedCount
    ) {
        uint256 startBlock = deployBlock + epochIndex * MDT_EPOCH_BLOCKS;
        uint256 endBlock = startBlock + MDT_EPOCH_BLOCKS;
        snapshotCount = 0;
        totalCalmScore = 0;
        attestedCount = 0;
        for (uint256 i = 0; i < _allSnapshotIds.length; i++) {
            MoodSnapshot storage s = snapshots[_allSnapshotIds[i]];
            if (s.atBlock >= startBlock && s.atBlock < endBlock) {
                snapshotCount++;
                totalCalmScore += s.calmScore;
                if (s.attested) attestedCount++;
            }
        }
        return (snapshotCount, totalCalmScore, attestedCount);
    }

    // -------------------------------------------------------------------------
    // COMPANION PROMPT LOOKUP BY BAND
    // -------------------------------------------------------------------------

    function getPromptIdsByBandHint(uint8 bandHint) external view returns (uint256[] memory) {
        uint256[] memory temp = new uint256[](MDT_MAX_PROMPTS);
        uint256 count = 0;
        for (uint256 i = 0; i < _allPromptIds.length; i++) {
            if (companionPrompts[_allPromptIds[i]].bandHint == bandHint) {
                temp[count] = _allPromptIds[i];
                count++;
            }
        }
        uint256[] memory out = new uint256[](count);
        for (uint256 j = 0; j < count; j++) out[j] = temp[j];
        return out;
    }

    // -------------------------------------------------------------------------
    // GAS ESTIMATION CONSTANTS (for frontends)
    // -------------------------------------------------------------------------

    uint256 public constant MDT_ESTIMATE_RECORD_SNAPSHOT = 95_000;
    uint256 public constant MDT_ESTIMATE_RECORD_BATCH_PER = 72_000;
    uint256 public constant MDT_ESTIMATE_ATTEST = 45_000;
    uint256 public constant MDT_ESTIMATE_STORE_PROMPT = 65_000;
    uint256 public constant MDT_ESTIMATE_AWARD_CALM = 55_000;
    uint256 public constant MDT_ESTIMATE_WITHDRAW_TREASURY = 38_000;

    // -------------------------------------------------------------------------
    // CALM POINTS BATCH (relay only)
    // -------------------------------------------------------------------------

    function awardCalmPointsBatch(address[] calldata users, uint256[] calldata amounts) external onlyPulseRelay whenNotPausedContract {
        if (users.length != amounts.length) revert MDT_ArrayLengthMismatch();
        if (users.length > MDT_BATCH_SIZE) revert MDT_BatchTooLarge();
        for (uint256 i = 0; i < users.length; i++) {
            if (users[i] == address(0) || amounts[i] == 0) continue;
            uint256 prev = userCalmBalance[users[i]];
            userCalmBalance[users[i]] = prev + amounts[i];
            emit CalmPointsAwarded(users[i], amounts[i], block.number);
            emit UserCalmBalanceUpdated(users[i], prev, prev + amounts[i]);
        }
    }

    // -------------------------------------------------------------------------
    // SENTIMENT BAND BATCH CONFIG
    // -------------------------------------------------------------------------

    function configureSentimentBandsBatch(
        uint8[] calldata bandIndices,
        uint256[] calldata minScores,
        uint256[] calldata maxScores
    ) external onlyCompanionKeeper {
        if (bandIndices.length != minScores.length || bandIndices.length != maxScores.length) revert MDT_ArrayLengthMismatch();
        if (bandIndices.length > MDT_BATCH_SIZE) revert MDT_BatchTooLarge();
        for (uint256 i = 0; i < bandIndices.length; i++) {
            uint8 bi = bandIndices[i];
            if (bi >= MDT_MAX_SENTIMENT_BANDS) continue;
            if (minScores[i] > maxScores[i] || maxScores[i] > MDT_SCORE_SCALE) continue;
            sentimentBands[bi] = SentimentBandConfig({
                minScore: minScores[i],
                maxScore: maxScores[i],
                lockedUntilBlock: 0,
                configured: true
            });
            emit SentimentBandConfigured(bi, minScores[i], maxScores[i], block.number);
        }
    }

    // -------------------------------------------------------------------------
    // PAUSE OVERRIDE (align with Pausable from OZ if needed)
    // -------------------------------------------------------------------------

    function paused() public view virtual override returns (bool) {
        return _pausedByRole || super.paused();
    }

    // -------------------------------------------------------------------------
    // SNAPSHOT PAGINATION (for frontends / Frankie)
    // -------------------------------------------------------------------------

    function getSnapshotIdsByUserPaginated(
        address user,
        uint256 offset,
        uint256 limit
    ) external view returns (uint256[] memory ids, uint256 total) {
        uint256[] storage all = _snapshotIdsByUser[user];
        total = all.length;
        if (offset >= total) return (new uint256[](0), total);
        uint256 remain = total - offset;
        if (limit > remain) limit = remain;
        if (limit > 64) limit = 64;
        ids = new uint256[](limit);
        for (uint256 i = 0; i < limit; i++) ids[i] = all[offset + i];
        return (ids, total);
    }

    function getGlobalSnapshotIdsPaginated(uint256 offset, uint256 limit) external view returns (uint256[] memory ids, uint256 total) {
        total = _allSnapshotIds.length;
        if (offset >= total) return (new uint256[](0), total);
        uint256 remain = total - offset;
        if (limit > remain) limit = remain;
        if (limit > 128) limit = 128;
        ids = new uint256[](limit);
        for (uint256 i = 0; i < limit; i++) ids[i] = _allSnapshotIds[offset + i];
        return (ids, total);
    }

    // -------------------------------------------------------------------------
    // MULTI-GET SNAPSHOTS (batch view to reduce RPC calls)
    // -------------------------------------------------------------------------

    function getSnapshotsByIds(uint256[] calldata snapshotIds) external view returns (
        address[] memory users,
        uint8[] memory bands,
        uint256[] memory scores,
        bytes32[] memory hashes,
        uint256[] memory blocks,
        bool[] memory attestedFlags
    ) {
        uint256 n = snapshotIds.length;
        if (n > 64) n = 64;
        users = new address[](n);
        bands = new uint8[](n);
        scores = new uint256[](n);
        hashes = new bytes32[](n);
        blocks = new uint256[](n);
        attestedFlags = new bool[](n);
        for (uint256 i = 0; i < n; i++) {
            MoodSnapshot storage s = snapshots[snapshotIds[i]];
            users[i] = s.user;
            bands[i] = s.sentimentBand;
            scores[i] = s.calmScore;
            hashes[i] = s.promptHash;
            blocks[i] = s.atBlock;
            attestedFlags[i] = s.attested;
        }
        return (users, bands, scores, hashes, blocks, attestedFlags);
    }

    // -------------------------------------------------------------------------
    // SENTIMENT BAND BOUNDS CHECK (view)
    // -------------------------------------------------------------------------

    function scoreFitsInBand(uint8 bandIndex, uint256 calmScore) external view returns (bool fits, bool bandConfigured) {
        if (bandIndex >= MDT_MAX_SENTIMENT_BANDS) return (false, false);
        SentimentBandConfig storage b = sentimentBands[bandIndex];
        bandConfigured = b.configured;
        if (!b.configured) return (calmScore <= MDT_SCORE_SCALE, false);
        if (b.lockedUntilBlock > block.number) return (false, true);
        fits = calmScore >= b.minScore && calmScore <= b.maxScore;
        return (fits, true);
    }

    function getBandBounds(uint8 bandIndex) external view returns (uint256 minScore, uint256 maxScore, bool locked) {
        if (bandIndex >= MDT_MAX_SENTIMENT_BANDS) return (0, 0, true);
        SentimentBandConfig storage b = sentimentBands[bandIndex];
        return (b.minScore, b.maxScore, b.lockedUntilBlock > block.number);
    }

    // -------------------------------------------------------------------------
    // CALM BALANCE BATCH VIEW
    // -------------------------------------------------------------------------

    function getCalmBalances(address[] calldata users) external view returns (uint256[] memory balances) {
        uint256 n = users.length;
        if (n > 64) n = 64;
        balances = new uint256[](n);
        for (uint256 i = 0; i < n; i++) balances[i] = userCalmBalance[users[i]];
        return balances;
    }

    // -------------------------------------------------------------------------
    // COMPANION PROMPTS BATCH VIEW
    // -------------------------------------------------------------------------

    function getPromptsByIds(uint256[] calldata promptIds) external view returns (
        bytes32[] memory contentHashes,
        uint8[] memory bandHints,
        uint256[] memory storedBlocks
    ) {
        uint256 n = promptIds.length;
        if (n > 64) n = 64;
        contentHashes = new bytes32[](n);
        bandHints = new uint8[](n);
        storedBlocks = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            CompanionPromptRecord storage p = companionPrompts[promptIds[i]];
            contentHashes[i] = p.contentHash;
            bandHints[i] = p.bandHint;
            storedBlocks[i] = p.storedAtBlock;
        }
        return (contentHashes, bandHints, storedBlocks);
    }

    // -------------------------------------------------------------------------
    // AGGREGATE STATS (global)
    // -------------------------------------------------------------------------

    function getGlobalStats() external view returns (
        uint256 totalSnapshotCount,
        uint256 totalPromptCount,
        uint256 totalTreasuryWei,
        uint256 totalCalmScoreSum,
        uint256 attestedCount
    ) {
        totalSnapshotCount = _allSnapshotIds.length;
        totalPromptCount = _allPromptIds.length;
        totalTreasuryWei = treasuryBalance;
        totalCalmScoreSum = 0;
        attestedCount = 0;
        for (uint256 i = 0; i < _allSnapshotIds.length; i++) {
            MoodSnapshot storage s = snapshots[_allSnapshotIds[i]];
            totalCalmScoreSum += s.calmScore;
            if (s.attested) attestedCount++;
        }
        return (totalSnapshotCount, totalPromptCount, totalTreasuryWei, totalCalmScoreSum, attestedCount);
    }

    // -------------------------------------------------------------------------
    // UNIQUE ADDRESSES (immutable; for verification / Frankie UI)
    // -------------------------------------------------------------------------

    function getImmutableAddresses() external view returns (
        address keeper,
        address vault,
        address oracle,
        address treasury,
        address relay
    ) {
        return (companionKeeper, moodVault, sentimentOracle, calmTreasury, pulseRelay);
    }

    function getDomainSalt() external view returns (bytes32) {
        return MDT_DOMAIN_SALT;
    }

    // -------------------------------------------------------------------------
    // FEE AND TREASURY VIEWS
    // -------------------------------------------------------------------------

    function getTreasuryBalance() external view returns (uint256) {
        return treasuryBalance;
    }

    function getCalmFeeWei() external view returns (uint256) {
        return calmFeeWei;
    }

    function estimateRecordFee(uint256 snapshotCount) external view returns (uint256 totalWei) {
        return calmFeeWei * snapshotCount;
    }

    // -------------------------------------------------------------------------
    // DEPLOY METADATA
    // -------------------------------------------------------------------------

    function getDeployMetadata() external view returns (uint256 blockNum, uint256 timestamp, bytes32 domainSalt) {
        return (deployBlock, deployTimestamp, MDT_DOMAIN_SALT);
    }

    // -------------------------------------------------------------------------
    // ROLE CHECK HELPERS (view)
    // -------------------------------------------------------------------------

    function isCompanionKeeper(address account) external view returns (bool) {
        return account == mdtCompanionKeeperRole || account == companionKeeper;
    }

    function isSentimentOracle(address account) external view returns (bool) {
        return account == mdtSentimentOracleRole || account == sentimentOracle;
    }

    function isMoodVault(address account) external view returns (bool) {
        return account == mdtMoodVaultRole || account == moodVault;
    }

    function isPulseRelay(address account) external view returns (bool) {
        return account == mdtPulseRelayRole || account == pulseRelay;
    }

    function isCalmTreasury(address account) external view returns (bool) {
        return account == calmTreasury;
    }

    // -------------------------------------------------------------------------
    // SENTIMENT BAND LABELS (optional; stored as bytes32 for gas)
    // -------------------------------------------------------------------------

    mapping(uint8 => bytes32) public bandLabelHash;

    function setBandLabelHash(uint8 bandIndex, bytes32 labelHash) external onlyCompanionKeeper {
        if (bandIndex >= MDT_MAX_SENTIMENT_BANDS) revert MDT_InvalidBandIndex();
        bandLabelHash[bandIndex] = labelHash;
    }

    function getBandLabelHashes(uint8 fromIndex, uint8 toIndex) external view returns (bytes32[] memory hashes) {
        if (toIndex > fromIndex + 32) toIndex = fromIndex + 32;
        if (toIndex >= MDT_MAX_SENTIMENT_BANDS) toIndex = MDT_MAX_SENTIMENT_BANDS - 1;
        uint256 n = toIndex >= fromIndex ? toIndex - fromIndex + 1 : 0;
        hashes = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            uint8 bi = uint8(fromIndex + i);
            hashes[i] = bandLabelHash[bi];
        }
        return hashes;
    }

    // -------------------------------------------------------------------------
    // LAST SNAPSHOT PER BAND (optional cache; updated on record)
    // -------------------------------------------------------------------------

    mapping(uint8 => uint256) public lastSnapshotIdByBand;

    function _updateLastSnapshotByBand(uint8 band) internal {
        if (band < MDT_MAX_SENTIMENT_BANDS) lastSnapshotIdByBand[band] = snapshotCounter;
    }

    // Override record to update lastSnapshotIdByBand - we do it in recordMoodSnapshot and recordMoodSnapshotBatch
    // (already have snapshotCounter at that point; call _updateLastSnapshotByBand(sentimentBand) after assigning snapshotId)

    // -------------------------------------------------------------------------
    // INTERNAL: update last snapshot by band (called from record functions)
    // -------------------------------------------------------------------------

    function getLastSnapshotIdForBand(uint8 bandIndex) external view returns (uint256) {
        if (bandIndex >= MDT_MAX_SENTIMENT_BANDS) return 0;
        return lastSnapshotIdByBand[bandIndex];
    }

    // -------------------------------------------------------------------------
    // EPOCH SNAPSHOT LIST (for Frankie dashboard)
    // -------------------------------------------------------------------------

    function getEpochSnapshotIds(uint256 epochIndex, uint256 maxReturn) external view returns (uint256[] memory ids) {
        uint256 startBlock = deployBlock + epochIndex * MDT_EPOCH_BLOCKS;
        uint256 endBlock = startBlock + MDT_EPOCH_BLOCKS;
        if (maxReturn > 128) maxReturn = 128;
        uint256[] memory temp = new uint256[](maxReturn);
        uint256 count = 0;
        for (uint256 i = _allSnapshotIds.length; i > 0 && count < maxReturn; i--) {
            uint256 sid = _allSnapshotIds[i - 1];
            MoodSnapshot storage s = snapshots[sid];
            if (s.atBlock >= startBlock && s.atBlock < endBlock) {
                temp[count] = sid;
                count++;
            }
        }
        ids = new uint256[](count);
        for (uint256 j = 0; j < count; j++) ids[j] = temp[j];
        return ids;
    }

    function getSnapshotDetails(uint256 snapshotId) external view returns (
        address user,
        uint8 sentimentBand,
        uint256 calmScore,
        bytes32 promptHash,
        uint256 atBlock,
        bool attested,
        uint256 bandMinScore,
        uint256 bandMaxScore
    ) {
        MoodSnapshot storage s = snapshots[snapshotId];
        user = s.user;
        sentimentBand = s.sentimentBand;
        calmScore = s.calmScore;
        promptHash = s.promptHash;
        atBlock = s.atBlock;
        attested = s.attested;
        if (s.sentimentBand < MDT_MAX_SENTIMENT_BANDS) {
            SentimentBandConfig storage b = sentimentBands[s.sentimentBand];
            bandMinScore = b.minScore;
            bandMaxScore = b.maxScore;
        } else {
            bandMinScore = 0;
            bandMaxScore = MDT_SCORE_SCALE;
        }
        return (user, sentimentBand, calmScore, promptHash, atBlock, attested, bandMinScore, bandMaxScore);
    }

    /// @notice Returns whether the contract is fully operational (not paused).
    function isOperational() external view returns (bool) {
        return !paused();
    }

    /// @notice Returns the number of configured sentiment bands (bands with configured == true).
    function getConfiguredBandCount() external view returns (uint8 count) {
        for (uint8 i = 0; i < MDT_MAX_SENTIMENT_BANDS; i++) {
            if (sentimentBands[i].configured) count++;
        }
        return count;
    }

    /// @notice Returns configured band indices (up to 16).
    function getConfiguredBandIndices() external view returns (uint8[] memory indices) {
        uint8[] memory temp = new uint8[](MDT_MAX_SENTIMENT_BANDS);
        uint8 count = 0;
        for (uint8 i = 0; i < MDT_MAX_SENTIMENT_BANDS; i++) {
            if (sentimentBands[i].configured) {
                temp[count] = i;
                count++;
            }
        }
        indices = new uint8[](count);
        for (uint8 j = 0; j < count; j++) indices[j] = temp[j];
        return indices;
    }

    /// @notice Compute average calm score across all snapshots (scaled by MDT_SCORE_SCALE).
    function getAverageCalmScore() external view returns (uint256 average) {
        uint256 total = _allSnapshotIds.length;
        if (total == 0) return 0;
        uint256 sum = 0;
        for (uint256 i = 0; i < total; i++) sum += snapshots[_allSnapshotIds[i]].calmScore;
        return sum / total;
    }

    /// @notice Compute average calm score for a given user.
    function getAverageCalmScoreForUser(address user) external view returns (uint256 average) {
        uint256[] storage ids = _snapshotIdsByUser[user];
        if (ids.length == 0) return 0;
        uint256 sum = 0;
        for (uint256 i = 0; i < ids.length; i++) sum += snapshots[ids[i]].calmScore;
        return sum / ids.length;
    }

    /// @notice Returns total calm points held by all users (sum of userCalmBalance).
    /// @dev Requires iterating; use sparingly. For large user sets consider off-chain indexing.
    function getTotalCalmPointsInCirculation() external view returns (uint256 total) {
        for (uint256 i = 0; i < _allSnapshotIds.length; i++) {
            address u = snapshots[_allSnapshotIds[i]].user;
            total += userCalmBalance[u];
        }
        return total;
    }

    /// @notice Check if a snapshot exists and is attested.
    function isSnapshotAttested(uint256 snapshotId) external view returns (bool) {
        return snapshots[snapshotId].attested;
    }

    /// @notice Get attestation status for a batch of snapshots.
    function getAttestationStatus(uint256[] calldata snapshotIds) external view returns (bool[] memory attested) {
        uint256 n = snapshotIds.length;
        if (n > 64) n = 64;
        attested = new bool[](n);
        for (uint256 i = 0; i < n; i++) attested[i] = snapshots[snapshotIds[i]].attested;
        return attested;
    }

    /// @notice Returns the companion prompt ID that best matches a band (latest stored for that band).
    function getLatestPromptIdForBand(uint8 bandHint) external view returns (uint256 promptId) {
        for (uint256 i = _allPromptIds.length; i > 0; i--) {
            uint256 pid = _allPromptIds[i - 1];
            if (companionPrompts[pid].bandHint == bandHint) return pid;
        }
        return 0;
    }

    // -------------------------------------------------------------------------
    // INTEGRATION / FRANKIE HELPERS
    // -------------------------------------------------------------------------

    /// @notice Single-call config for frontends: addresses, fee, treasury, pause, counts.
    function getFrontendConfig() external view returns (
        address keeper_,
        address vault_,
        address oracle_,
        address treasury_,
        address relay_,
        uint256 calmFeeWei_,
        uint256 treasuryBalance_,
        bool paused_,
        uint256 snapshotCount_,
        uint256 promptCount_,
        uint256 deployBlock_
    ) {
        return (
            mdtCompanionKeeperRole,
            mdtMoodVaultRole,
            mdtSentimentOracleRole,
            calmTreasury,
            mdtPulseRelayRole,
            calmFeeWei,
            treasuryBalance,
            paused(),
            _allSnapshotIds.length,
            _allPromptIds.length,
            deployBlock
        );
    }

    /// @notice Returns snapshot IDs for a user in reverse order (newest first), with limit.
    function getSnapshotIdsByUserLatest(address user, uint256 limit) external view returns (uint256[] memory ids) {
        uint256[] storage all = _snapshotIdsByUser[user];
        if (limit > 64) limit = 64;
        uint256 total = all.length;
        if (total == 0) return new uint256[](0);
        uint256 take = limit > total ? total : limit;
        ids = new uint256[](take);
        for (uint256 i = 0; i < take; i++) ids[i] = all[total - 1 - i];
        return ids;
    }

    /// @notice Returns the current epoch index and block range for that epoch.
    function getEpochBlockRange(uint256 epochIndex) external view returns (uint256 startBlock, uint256 endBlock) {
        startBlock = deployBlock + epochIndex * MDT_EPOCH_BLOCKS;
        endBlock = startBlock + MDT_EPOCH_BLOCKS;
        return (startBlock, endBlock);
    }

    /// @notice Returns whether the caller has any role (keeper, oracle, vault, relay) or is treasury.
    function hasAnyRole(address account) external view returns (bool) {
        return account == mdtCompanionKeeperRole || account == companionKeeper
            || account == mdtSentimentOracleRole || account == sentimentOracle
            || account == mdtMoodVaultRole || account == moodVault
            || account == mdtPulseRelayRole || account == pulseRelay
            || account == calmTreasury;
    }

    // -------------------------------------------------------------------------
    // CONSTANTS REFERENCE (no-op view for documentation / tooling)
    // -------------------------------------------------------------------------

    function getConstants() external pure returns (
        uint256 scoreScale,
        uint256 maxSentimentBands,
        uint256 maxSnapshotsPerUser,
        uint256 maxPrompts,
        uint256 batchSize,
        uint256 bandLockBlocks,
        uint256 epochBlocks
    ) {
        return (
            MDT_SCORE_SCALE,
            MDT_MAX_SENTIMENT_BANDS,
            MDT_MAX_SNAPSHOTS_PER_USER,
            MDT_MAX_PROMPTS,
            MDT_BATCH_SIZE,
            MDT_BAND_LOCK_BLOCKS,
            MDT_EPOCH_BLOCKS
        );
    }

    // -------------------------------------------------------------------------
    // GAS ESTIMATES (view)
    // -------------------------------------------------------------------------

    function estimateRecordSnapshotGas() external pure returns (uint256) {
        return MDT_ESTIMATE_RECORD_SNAPSHOT;
    }

    function estimateRecordBatchGas(uint256 count) external pure returns (uint256) {
        if (count > MDT_BATCH_SIZE) return MDT_ESTIMATE_RECORD_BATCH_PER * MDT_BATCH_SIZE;
        return MDT_ESTIMATE_RECORD_BATCH_PER * count;
    }

    function estimateAttestGas() external pure returns (uint256) {
        return MDT_ESTIMATE_ATTEST;
    }

    function estimateStorePromptGas() external pure returns (uint256) {
        return MDT_ESTIMATE_STORE_PROMPT;
    }

    function estimateAwardCalmGas() external pure returns (uint256) {
        return MDT_ESTIMATE_AWARD_CALM;
    }

    function estimateWithdrawTreasuryGas() external pure returns (uint256) {
        return MDT_ESTIMATE_WITHDRAW_TREASURY;
    }

    // -------------------------------------------------------------------------
    // SENTIMENT BAND FULL CONFIG BATCH (for Frankie band editor)
    // -------------------------------------------------------------------------

    function getAllBandConfigs() external view returns (
        uint8[] memory indices,
        uint256[] memory minScores,
        uint256[] memory maxScores,
        uint256[] memory lockedUntilBlocks,
        bool[] memory configured
    ) {
        indices = new uint8[](MDT_MAX_SENTIMENT_BANDS);
        minScores = new uint256[](MDT_MAX_SENTIMENT_BANDS);
        maxScores = new uint256[](MDT_MAX_SENTIMENT_BANDS);
        lockedUntilBlocks = new uint256[](MDT_MAX_SENTIMENT_BANDS);
        configured = new bool[](MDT_MAX_SENTIMENT_BANDS);
        for (uint8 i = 0; i < MDT_MAX_SENTIMENT_BANDS; i++) {
            indices[i] = i;
            SentimentBandConfig storage b = sentimentBands[i];
            minScores[i] = b.minScore;
            maxScores[i] = b.maxScore;
            lockedUntilBlocks[i] = b.lockedUntilBlock;
            configured[i] = b.configured;
        }
        return (indices, minScores, maxScores, lockedUntilBlocks, configured);
    }

    /// @notice Returns the number of snapshots recorded in a given block range (inclusive).
    function getSnapshotCountInBlockRange(uint256 fromBlock, uint256 toBlock) external view returns (uint256 count) {
        for (uint256 i = 0; i < _allSnapshotIds.length; i++) {
            uint256 blk = snapshots[_allSnapshotIds[i]].atBlock;
            if (blk >= fromBlock && blk <= toBlock) count++;
        }
        return count;
    }

    /// @notice Returns the number of distinct users who have recorded at least one snapshot (capped at 256 per call).
    function getUniqueUserCount() external view returns (uint256 count) {
        address[256] memory seen;
        uint256 len = 0;
        for (uint256 i = 0; i < _allSnapshotIds.length && len < 256; i++) {
            address u = snapshots[_allSnapshotIds[i]].user;
            bool found = false;
            for (uint256 j = 0; j < len; j++) {
                if (seen[j] == u) { found = true; break; }
            }
            if (!found) {
                seen[len] = u;
                len++;
            }
        }
        return len;
    }

    /// @notice Simple existence check for snapshot.
    function snapshotExists(uint256 snapshotId) external view returns (bool) {
        return snapshots[snapshotId].user != address(0);
    }

    /// @notice Simple existence check for prompt.
    function promptExists(uint256 promptId) external view returns (bool) {
        return companionPrompts[promptId].storedAtBlock != 0;
    }

    // -------------------------------------------------------------------------
    // ADDITIONAL VIEWS FOR ANALYTICS
    // -------------------------------------------------------------------------

    /// @notice Returns calm score distribution: count of snapshots per band for a user.
    function getUserBandDistribution(address user) external view returns (uint256[] memory counts) {
        counts = new uint256[](MDT_MAX_SENTIMENT_BANDS);
        uint256[] storage ids = _snapshotIdsByUser[user];
        for (uint256 i = 0; i < ids.length; i++) {
            uint8 b = snapshots[ids[i]].sentimentBand;
            if (b < MDT_MAX_SENTIMENT_BANDS) counts[b]++;
        }
        return counts;
    }

    /// @notice Returns the highest calm score ever recorded for a user.
    function getMaxCalmScoreForUser(address user) external view returns (uint256 maxScore) {
        uint256[] storage ids = _snapshotIdsByUser[user];
        for (uint256 i = 0; i < ids.length; i++) {
            uint256 s = snapshots[ids[i]].calmScore;
            if (s > maxScore) maxScore = s;
        }
        return maxScore;
    }

    /// @notice Returns the lowest calm score ever recorded for a user (ignoring zero).
    function getMinCalmScoreForUser(address user) external view returns (uint256 minScore) {
        uint256[] storage ids = _snapshotIdsByUser[user];
        if (ids.length == 0) return MDT_SCORE_SCALE;
        minScore = MDT_SCORE_SCALE;
        for (uint256 i = 0; i < ids.length; i++) {
            uint256 s = snapshots[ids[i]].calmScore;
            if (s < minScore) minScore = s;
        }
        return minScore;
    }

    /// @notice Returns block number of the first and last snapshot for a user.
    function getUserSnapshotBlockRange(address user) external view returns (uint256 firstBlock, uint256 lastBlock) {
        uint256[] storage ids = _snapshotIdsByUser[user];
        if (ids.length == 0) return (0, 0);
        firstBlock = snapshots[ids[0]].atBlock;
        lastBlock = snapshots[ids[ids.length - 1]].atBlock;
        return (firstBlock, lastBlock);
    }

    /// @notice Returns the attestation rate (attested count / total) for a user.
    function getUserAttestationRate(address user) external view returns (uint256 attested, uint256 total) {
        uint256[] storage ids = _snapshotIdsByUser[user];
        total = ids.length;
        for (uint256 i = 0; i < ids.length; i++) {
            if (snapshots[ids[i]].attested) attested++;
        }
        return (attested, total);
    }

    /// @notice Returns the attestation rate globally.
    function getGlobalAttestationRate() external view returns (uint256 attested, uint256 total) {
        total = _allSnapshotIds.length;
        for (uint256 i = 0; i < _allSnapshotIds.length; i++) {
            if (snapshots[_allSnapshotIds[i]].attested) attested++;
        }
        return (attested, total);
    }

