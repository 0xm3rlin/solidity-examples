// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "../OFTCore.sol";
import "./IComposableOFTCore.sol";
import "../../../util/ExcessivelySafeCall.sol";

abstract contract ComposableOFTCore is OFTCore, IComposableOFTCore {
    using ExcessivelySafeCall for address;
    using BytesLib for bytes;

    // packet type
    uint16 public constant PT_SEND_AND_CALL = 1;

    mapping(uint16 => mapping(bytes => mapping(uint64 => bytes32))) public failedOFTReceivedMessages;

    constructor(address _lzEndpoint) OFTCore(_lzEndpoint) {}

    function supportsInterface(bytes4 interfaceId) public view virtual override(OFTCore, IERC165) returns (bool) {
        return interfaceId == type(IComposableOFTCore).interfaceId || super.supportsInterface(interfaceId);
    }

    function estimateSendAndCallFee(address _from, uint16 _dstChainId, bytes calldata _toAddress, uint _amount, bytes calldata _payload, uint _dstGasForCall, bool _useZro, bytes calldata _adapterParams) public view virtual override returns (uint nativeFee, uint zroFee) {
        // mock the payload for sendAndCall()
        bytes memory payload = abi.encode(PT_SEND_AND_CALL, abi.encodePacked(msg.sender), abi.encodePacked(_from), _toAddress, _amount, _payload, _dstGasForCall);
        return lzEndpoint.estimateFees(_dstChainId, address(this), payload, _useZro, _adapterParams);
    }

    function sendAndCall(address _from, uint16 _dstChainId, bytes calldata _toAddress, uint _amount, bytes calldata _payload, uint _dstGasForCall, address payable _refundAddress, address _zroPaymentAddress, bytes calldata _adapterParams) public payable virtual override {
        _sendAndCall(_from, _dstChainId, _toAddress, _amount, _payload, _dstGasForCall, _refundAddress, _zroPaymentAddress, _adapterParams);
    }

    function retryOFTReceived(uint16 _srcChainId, bytes calldata _srcAddress, uint64 _nonce, bytes calldata _from, address _to, uint _amount, bytes calldata _payload) public virtual override {
        bytes32 msgHash = failedOFTReceivedMessages[_srcChainId][_srcAddress][_nonce];
        require(msgHash != bytes32(0), "ComposableOFTCore: no failed message to retry");

        bytes32 hash = keccak256(abi.encode( _to, _amount, _payload));
        require(hash == msgHash, "ComposableOFTCore: failed message hash mismatch");

        delete failedOFTReceivedMessages[_srcChainId][_srcAddress][_nonce];

        (bool success, ) = _to.call(_payload);

        if (success) {
            _creditTo(_srcChainId, to, amount);
            emit ReceiveFromChain(_srcChainId, _from, _to, _amount);
        } else revert();
        emit RetryOFTReceivedSuccess(hash);
    }

    function _nonblockingLzReceive(uint16 _srcChainId, bytes memory _srcAddress, uint64 _nonce, bytes memory _payload) internal virtual override {
        uint16 packetType;
        assembly {
            packetType := mload(add(_payload, 32))
        }

        if (packetType == PT_SEND) {
            _sendAck(_srcChainId, _srcAddress, _nonce, _payload);
        } else if (packetType == PT_SEND_AND_CALL) {
            _sendAndCallAck(_srcChainId, _srcAddress, _nonce, _payload);
        } else {
            revert("ComposableOFTCore: unknown packet type");
        }
    }

    function _sendAndCall(address _from, uint16 _dstChainId, bytes memory _toAddress, uint _amount, bytes calldata _payload, uint _dstGasForCall, address payable _refundAddress, address _zroPaymentAddress, bytes memory _adapterParams) internal virtual {
        _checkAdapterParams(_dstChainId, PT_SEND_AND_CALL, _adapterParams, _dstGasForCall);

        _debitFrom(_from, _dstChainId, _toAddress, _amount);

        bytes memory lzPayload = abi.encode(PT_SEND_AND_CALL, abi.encodePacked(msg.sender), abi.encodePacked(_from), _toAddress, _amount, _payload, _dstGasForCall);
        _lzSend(_dstChainId, lzPayload, _refundAddress, _zroPaymentAddress, _adapterParams, msg.value);

        emit SendToChain(_dstChainId, _from, _toAddress, _amount);
    }

    function _sendAndCallAck(uint16 _srcChainId, bytes memory _srcAddress, uint64 _nonce, bytes memory _payload) internal virtual {
        (, bytes memory from, bytes memory toAddressBytes, uint amount, bytes memory payload, uint gasForCall) = abi.decode(_payload, (uint16, bytes, bytes, uint, bytes, uint));

        address to = toAddressBytes.toAddress(0);

        if (!_isContract(to)) {
            emit NonContractAddress(to);
            return;
        }

        (bool success, ) = _safeCallOnOFTReceived(_srcChainId, _srcAddress, _nonce, to, amount, payload, gasForCall);

        if (success) {
            _creditTo(_srcChainId, to, amount);
            emit ReceiveFromChain(_srcChainId, from, to, amount);
        }
    }

    function _safeCallOnOFTReceived(uint16 _srcChainId, bytes memory _srcAddress, uint64 _nonce, address _to, uint _amount, bytes memory _payload, uint _gasForCall) internal virtual returns (bool success, bytes memory reason) {
        (success, reason) = _to.excessivelySafeCall(_gasForCall, 150, _payload);
        if (!success) {
            failedOFTReceivedMessages[_srcChainId][_srcAddress][_nonce] = keccak256(abi.encode(_to, _amount, _payload));
            emit CallOFTReceivedFailure(_srcChainId, _srcAddress, _nonce, _to, _amount, _payload, reason);
        } else {
            bytes32 hash = keccak256(abi.encode( _to, _amount, _payload));
            emit CallOFTReceivedSuccess(_srcChainId, _srcAddress, _nonce, hash);
        }
    }

    function _isContract(address _account) internal view returns (bool) {
        return _account.code.length > 0;
    }
}
