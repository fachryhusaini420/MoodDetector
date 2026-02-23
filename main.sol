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
