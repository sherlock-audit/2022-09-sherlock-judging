csanuragjain
# Unregulated joining fees

## Summary
tfUSDC.join deducts fees from deposited balance. Now this fees is unregulated and could be 100% of amount passed as can be seen at setJoiningFee function at https://github.com/trusttoken/contracts-pre22/blob/main/contracts/truefi2/TrueFiPool2.sol#L449. Since minting will not fail even with zero amount, our contract will end up everything given as fees

## Vulnerability Detail
1. Observe the _deposit function

```python
function _deposit() internal override whenNotPaused {
    // https://github.com/trusttoken/contracts-pre22/blob/main/contracts/truefi2/TrueFiPool2.sol#L469
    tfUSDC.join(want.balanceOf(address(this)));
...
}
```

2. This makes call to [join function](https://github.com/trusttoken/contracts-pre22/blob/main/contracts/truefi2/TrueFiPool2.sol#L469)

```python
function join(uint256 amount) external override joiningNotPaused {
        uint256 fee = amount.mul(joiningFee).div(BASIS_PRECISION);
        uint256 mintedAmount = mint(amount.sub(fee));
        claimableFees = claimableFees.add(fee);

        // TODO: tx.origin will be deprecated in a future ethereum upgrade
        latestJoinBlock[tx.origin] = block.number;
        token.safeTransferFrom(msg.sender, address(this), amount);

        emit Joined(msg.sender, amount, mintedAmount);
    }
```

3. As we can see this join function deducts a fees from the deposited amount before minting. Lets see this joining fees
4. The joining fees is introduced using [setJoiningFee function](https://github.com/trusttoken/contracts-pre22/blob/main/contracts/truefi2/TrueFiPool2.sol#L449)

```python
function setJoiningFee(uint256 fee) external onlyOwner {
        require(fee <= BASIS_PRECISION, "TrueFiPool: Fee cannot exceed transaction value");
        joiningFee = fee;
        emit JoiningFeeChanged(fee);
    }
```

5. This means the joiningFee will always be in between 0 to BASIS_PRECISION. This BASIS_PRECISION can be 100% as shown

```python
uint256 private constant BASIS_PRECISION = 10000;
```

6. This means if joiningFee is set to BASIS_PRECISION then all user deposit will goto joining fees with user getting nothing

## Impact
Contract will lose all deposited funds

## Code Snippet
https://github.com/None/blob/None/sherlock-v2-core/contracts/strategy/TrueFiStrategy.sol#L90

## Tool used
Manual Review

## Recommendation
Post calling join, check amount of shares minted for this user (use balanceOF on TrueFiPool2.sol) and if it is below minimum expected revert the transaction

```python
uint256 tfUsdcBalance = tfUSDC.balanceOf(address(this));
require(tfUsdcBalance>=minSharesExpected, "Too high fees");
```