// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.0) (governance/extensions/GovernorCountingSimple.sol)

pragma solidity ^0.8.0;

import "./GovernorUpgradeableV2.sol";
import "@openzeppelin/contracts-upgradeable-v4/proxy/utils/Initializable.sol";
import "fhevm/contracts/lib/TFHE.sol";
import "fhevm/contracts/lib/Gateway.sol";

/**
 * Modifications:
 * - Inherited `GovernorUpgradeableV2`
 * - Made _proposalVotes internal
 * - Added async decryption functionality
 */
abstract contract GovernorCountingSimpleUpgradeableV2 is Initializable, GovernorUpgradeableV2, GatewayCaller {
    function __GovernorCountingSimple_init() internal onlyInitializing {}

    function __GovernorCountingSimple_init_unchained() internal onlyInitializing {}

    enum VoteType {
        Against,
        For,
        Abstain
    }

    struct ProposalVote {
        euint32 againstVotes;
        euint32 forVotes;
        euint32 abstainVotes;
        mapping(address => bool) hasVoted;
    }

    mapping(uint256 => ProposalVote) internal _proposalVotes;

    // New mappings for async decryption
    mapping(uint256 => bytes32) private _decryptionRequests;
    mapping(uint256 => uint32[]) private _decryptedTallies;

    // Add a new enum for DecryptionState
    enum DecryptionState {
        NotRequested,
        Requested,
        Completed
    }

    // Add a mapping to track decryption state
    mapping(uint256 => DecryptionState) private _decryptionState;

    /**
     * @dev See {IGovernor-COUNTING_MODE}.
     */
    // solhint-disable-next-line func-name-mixedcase
    function COUNTING_MODE() public pure virtual override returns (string memory) {
        return "support=bravo&quorum=for,abstain";
    }

    /**
     * @dev See {IGovernor-hasVoted}.
     */
    function hasVoted(uint256 proposalId, address account) public view virtual override returns (bool) {
        return _proposalVotes[proposalId].hasVoted[account];
    }

    /**
     * @dev Accessor to the internal vote counts.
     */
    function proposalVotes(
        uint256 proposalId
    ) public view virtual returns (euint32 againstVotes, euint32 forVotes, euint32 abstainVotes) {
        ProposalVote storage proposalVote = _proposalVotes[proposalId];
        return (proposalVote.againstVotes, proposalVote.forVotes, proposalVote.abstainVotes);
    }

    /**
     * @dev See {Governor-_quorumReached}.
     */
    function _quorumReached(uint256 proposalId) internal view virtual returns (ebool) {
        ProposalVote storage proposalVote = _proposalVotes[proposalId];
        euint32 quorumVotes = TFHE.asEuint32(uint32(quorum(proposalSnapshot(proposalId))));
        euint32 totalVotes = TFHE.add(proposalVote.forVotes, proposalVote.abstainVotes);
        return TFHE.ge(totalVotes, quorumVotes);
    }

    /**
     * @dev See {Governor-_voteSucceeded}. In this module, the forVotes must be strictly over the againstVotes.
     */
    function _voteSucceeded(uint256 proposalId) internal view virtual returns (ebool) {
        ProposalVote storage proposalVote = _proposalVotes[proposalId];
        return TFHE.gt(proposalVote.forVotes, proposalVote.againstVotes);
    }

    /**
     * @dev See {Governor-_countVote}. In this module, the support follows the `VoteType` enum (from Governor Bravo).
     */
    function _countVote(
        uint256 proposalId,
        address account,
        bytes calldata encryptedSupport,
        bytes calldata encryptedWeight,
        bytes memory // params
    ) internal virtual override {
        ProposalVote storage proposalVote = _proposalVotes[proposalId];

        require(!proposalVote.hasVoted[account], "GovernorVotingSimple: vote already cast");
        proposalVote.hasVoted[account] = true;

        euint8 support = TFHE.asEuint8(encryptedSupport);
        euint32 weight = TFHE.asEuint32(encryptedWeight);

        proposalVote.againstVotes = TFHE.add(
            proposalVote.againstVotes,
            TFHE.cmux(TFHE.eq(support, TFHE.asEuint8(uint8(VoteType.Against))), weight, TFHE.asEuint32(0))
        );
        proposalVote.forVotes = TFHE.add(
            proposalVote.forVotes,
            TFHE.cmux(TFHE.eq(support, TFHE.asEuint8(uint8(VoteType.For))), weight, TFHE.asEuint32(0))
        );
        proposalVote.abstainVotes = TFHE.add(
            proposalVote.abstainVotes,
            TFHE.cmux(TFHE.eq(support, TFHE.asEuint8(uint8(VoteType.Abstain))), weight, TFHE.asEuint32(0))
        );
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[49] private __gap;

    // Override the state function
    function state(uint256 proposalId) public view virtual override returns (ProposalState) {
        ProposalState currentState = super.state(proposalId);

        if (currentState == ProposalState.Succeeded || currentState == ProposalState.Defeated) {
            if (_decryptionState[proposalId] == DecryptionState.NotRequested) {
                return ProposalState.AwaitingDecryption;
            } else if (_decryptionState[proposalId] == DecryptionState.Requested) {
                return ProposalState.DecryptionInProgress;
            }
        }

        return currentState;
    }

    // Override the execute function
    function execute(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) public payable virtual override returns (uint256) {
        uint256 proposalId = hashProposal(targets, values, calldatas, descriptionHash);

        ProposalState status = state(proposalId);
        require(status == ProposalState.Succeeded, "Governor: proposal not successful");

        require(_decryptionState[proposalId] == DecryptionState.Completed, "Governor: tally not yet decrypted");

        _execute(proposalId, targets, values, calldatas, descriptionHash);

        emit ProposalExecuted(proposalId);

        return proposalId;
    }

    // New function to request async decryption of tally
    function requestTallyDecryption(uint256 proposalId) external onlyAuthorizedRevealer {
        ProposalState status = state(proposalId);
        require(status == ProposalState.AwaitingDecryption, "GovernorCountingSimple: invalid state for decryption");

        ProposalVote storage proposalVote = _proposalVotes[proposalId];
        euint32[] memory encryptedVotes = new euint32[](3);
        encryptedVotes[0] = proposalVote.againstVotes;
        encryptedVotes[1] = proposalVote.forVotes;
        encryptedVotes[2] = proposalVote.abstainVotes;

        bytes32 requestId = Gateway.requestDecryption(encryptedVotes, abi.encode(proposalId));
        _decryptionRequests[proposalId] = requestId;
        _decryptionState[proposalId] = DecryptionState.Requested;

        emit TallyDecryptionRequested(proposalId, requestId);
    }

    // Callback function for async decryption
    function onDecryptionResult(bytes32 requestId, uint256[] memory decryptedValues) external onlyGateway {
        uint256 proposalId = abi.decode(Gateway.getRequestData(requestId), (uint256));
        require(_decryptionRequests[proposalId] == requestId, "GovernorCountingSimple: invalid request ID");

        uint32[] memory tally = new uint32[](decryptedValues.length);
        for (uint i = 0; i < decryptedValues.length; i++) {
            tally[i] = uint32(decryptedValues[i]);
        }

        _decryptedTallies[proposalId] = tally;
        delete _decryptionRequests[proposalId];
        _decryptionState[proposalId] = DecryptionState.Completed;

        emit TallyDecrypted(proposalId, tally[0], tally[1], tally[2]);
    }

    // Function to get decrypted tally
    function getDecryptedTally(uint256 proposalId) external view returns (uint32, uint32, uint32) {
        require(_decryptedTallies[proposalId].length == 3, "GovernorCountingSimple: tally not decrypted yet");
        return (_decryptedTallies[proposalId][0], _decryptedTallies[proposalId][1], _decryptedTallies[proposalId][2]);
    }

    // Events
    event TallyDecryptionRequested(uint256 indexed proposalId, bytes32 requestId);
    event TallyDecrypted(uint256 indexed proposalId, uint32 againstVotes, uint32 forVotes, uint32 abstainVotes);

    // Modifier to restrict access to authorized revealers
    modifier onlyAuthorizedRevealer() {
        require(
            IGovernorUpgradeable(address(this)).isAuthorizedRevealer(msg.sender),
            "GovernorCountingSimple: not an authorized revealer"
        );
        _;
    }

    uint256[49] private __gap;
}
