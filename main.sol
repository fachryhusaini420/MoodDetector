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
