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
