Bnke0x0
# ERC20 return values not checked

## Summary
The `ERC20.transfer()` and `ERC20.transferFrom()` functions return a boolean value indicating success. This parameter needs to be checked for success. Some tokens do **not** revert if the transfer failed but return `false` instead. Tokens that don't actually perform the transfer and return `false` are still counted as a correct transfer.

## Vulnerability Detail

## Impact

## Code Snippet
https://github.com/None/blob/None/sherlock-v2-core/contracts/util/StrategyMock.sol#L35

    'want.transfer(msg.sender, _amount);'

https://github.com/None/blob/None/sherlock-v2-core/contracts/util/TreeSplitterMock.sol#L36

    'want.transfer(address(childOne), balance);'

https://github.com/None/blob/None/sherlock-v2-core/contracts/util/TreeSplitterMock.sol#L40

    'want.transfer(address(childTwo), balance);'


https://github.com/None/blob/None/sherlock-v2-core/contracts/util/TreeStrategyMock.sol#L40

    'want.transfer(msg.sender, amount);'

https://github.com/None/blob/None/sherlock-v2-core/contracts/util/TreeStrategyMock.sol#L48

    'want.transfer(msg.sender, _amount);'

https://github.com/None/blob/None/sherlock-v2-core/contracts/util/TreeSplitterMock.sol#L122

    'want.transfer(address(core), _amount);'

https://github.com/None/blob/None/sherlock-v2-core/contracts/util/TreeSplitterMock.sol#L131

    'want.transfer(address(core), b);'
## Tool used

Manual Review

## Recommendation
As the Sherlock event token can be any token, all interactions with it should follow correct EIP20 checks. We recommend checking the success boolean of all .transfer and .transferFrom calls for the unknown token contract.