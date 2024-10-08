// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import { IProposalTypesConfigurator } from "contracts/interfaces/IProposalTypesConfigurator.sol";
import { IAgoraGovernor } from "contracts/interfaces/IAgoraGovernor.sol";

/**
 * Contract that stores proposalTypes for the Agora Governor.
 */
contract ProposalTypesConfigurator is IProposalTypesConfigurator {
    /*//////////////////////////////////////////////////////////////
                           IMMUTABLE STORAGE
    //////////////////////////////////////////////////////////////*/

    IAgoraGovernor public governor;
    uint16 public constant PERCENT_DIVISOR = 10_000;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    mapping(uint8 proposalTypeId => ProposalType) internal _proposalTypes;
    mapping(uint8 proposalTypeId => bool) internal _proposalTypesExists;
    mapping(uint8 proposalTypeId => Scope[]) public scopes;
    mapping(uint8 proposalTypeId => mapping(bytes32 typeHash => bool)) public scopeExists;

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyAdminOrTimelock() {
        if (msg.sender != governor.admin() && msg.sender != governor.timelock()) revert NotAdminOrTimelock();
        _;
    }

    modifier onlyAdmin() {
        if (msg.sender != governor.admin()) revert NotAdmin();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize the contract with the governor and proposal types.
     * @param _governor Address of the governor contract.
     * @param _proposalTypesInit Array of ProposalType structs to initialize the contract with.
     */
    function initialize(address _governor, ProposalType[] calldata _proposalTypesInit) external {
        if (address(governor) != address(0)) revert AlreadyInit();
        governor = IAgoraGovernor(_governor);
        for (uint8 i = 0; i < _proposalTypesInit.length; i++) {
            _setProposalType(
                i,
                _proposalTypesInit[i].quorum,
                _proposalTypesInit[i].approvalThreshold,
                _proposalTypesInit[i].name,
                _proposalTypesInit[i].module,
                _proposalTypesInit[i].txTypeHashes
            );
        }
    }

    /**
     * @notice Get the parameters for a proposal type.
     * @param proposalTypeId Id of the proposal type.
     * @return ProposalType struct of of the proposal type.
     */
    function proposalTypes(uint8 proposalTypeId) external view override returns (ProposalType memory) {
        return _proposalTypes[proposalTypeId];
    }

    /**
     * @notice Sets the scope for a given proposal type.
     * @param proposalTypeId Id of the proposal type.
     * @param txTypeHash A function selector that represent the type hash, i.e. keccak256("foobar(uint,address)").
     * @param encodedLimit An ABI encoded string containing the function selector and relevant parameter values.
     * @param parameters The list of byte represented values to be compared against the encoded limits.
     * @param comparators List of enumuerated values represent which comparison to use when enforcing limit checks on parameters.
     */
    function setScopeForProposalType(
        uint8 proposalTypeId,
        bytes32 txTypeHash,
        bytes calldata encodedLimit,
        bytes[] memory parameters,
        Comparators[] memory comparators
    ) external override onlyAdmin {
        if (!_proposalTypesExists[proposalTypeId]) revert InvalidProposalType();
        if (parameters.length != comparators.length) revert InvalidParameterConditions();
        if (scopeExists[proposalTypeId][txTypeHash]) revert NoDuplicateTxTypes(); // Do not allow multiple scopes for a single transaction type

        for (uint8 i = 0; i < _proposalTypes[proposalTypeId].txTypeHashes.length; i++) {
            if (_proposalTypes[proposalTypeId].txTypeHashes[i] == txTypeHash) {
                revert NoDuplicateTxTypes();
            }
        }

        Scope memory scope = Scope(txTypeHash, encodedLimit, parameters, comparators);
        scopes[proposalTypeId].push(scope);

        scopeExists[proposalTypeId][txTypeHash] = true;

        _proposalTypes[proposalTypeId].txTypeHashes.push(txTypeHash);
    }

    /**
     * @notice Set the parameters for a proposal type. Only callable by the admin or timelock.
     * @param proposalTypeId Id of the proposal type
     * @param quorum Quorum percentage, scaled by `PERCENT_DIVISOR`
     * @param approvalThreshold Approval threshold percentage, scaled by `PERCENT_DIVISOR`
     * @param name Name of the proposal type
     * @param module Address of module that can only use this proposal type
     * @param txTypeHashes A list of transaction function selectors that represent the type hash, i.e. keccak256("foobar(uint,address)")
     */
    function setProposalType(
        uint8 proposalTypeId,
        uint16 quorum,
        uint16 approvalThreshold,
        string calldata name,
        address module,
        bytes32[] memory txTypeHashes
    ) external override onlyAdminOrTimelock {
        _setProposalType(proposalTypeId, quorum, approvalThreshold, name, module, txTypeHashes);
    }

    function _setProposalType(
        uint8 proposalTypeId,
        uint16 quorum,
        uint16 approvalThreshold,
        string calldata name,
        address module,
        bytes32[] memory txTypeHashes
    ) internal {
        if (quorum > PERCENT_DIVISOR) revert InvalidQuorum();
        if (approvalThreshold > PERCENT_DIVISOR) revert InvalidApprovalThreshold();

        _proposalTypes[proposalTypeId] = ProposalType(quorum, approvalThreshold, name, module, txTypeHashes);
        _proposalTypesExists[proposalTypeId] = true;

        emit ProposalTypeSet(proposalTypeId, quorum, approvalThreshold, name, txTypeHashes);
    }

    /**
     * @notice Adds an additional scope for a given proposal type.
     * @param proposalTypeId Id of the proposal type
     * @param scope An object that contains the scope for a transaction type hash
     */
    function updateScopeForProposalType(uint8 proposalTypeId, Scope calldata scope) external override onlyAdmin {
        if (!_proposalTypesExists[proposalTypeId]) revert InvalidProposalType();
        if (scope.parameters.length != scope.comparators.length) revert InvalidParameterConditions();
        if (scopeExists[proposalTypeId][scope.txTypeHash]) revert NoDuplicateTxTypes(); // Do not allow multiple scopes for a single transaction type

        scopes[proposalTypeId].push(scope);
        scopeExists[proposalTypeId][scope.txTypeHash] = true;
    }

    /**
     * @notice Retrives the encoded limit of a transaction type signature for a given proposal type.
     * @param proposalTypeId Id of the proposal type
     * @param txTypeHash A type signature of a function that has a limit specified in a scope
     */
    function getLimit(uint8 proposalTypeId, bytes32 txTypeHash) public view returns (bytes memory encodedLimits) {
        if (!_proposalTypesExists[proposalTypeId]) revert InvalidProposalType();

        if (!scopeExists[proposalTypeId][txTypeHash]) revert InvalidScope();
        Scope[] memory validScopes = scopes[proposalTypeId];

        for (uint8 i = 0; i < validScopes.length; i++) {
            if (validScopes[i].txTypeHash == txTypeHash) {
                return validScopes[i].encodedLimits;
            }
        }
    }
}
