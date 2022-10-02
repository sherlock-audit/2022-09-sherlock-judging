minhquanym
# Claimed reward is not sent to liquidity mining immediately

## Vulnerability Detail
https://github.com/None/blob/None/sherlock-v2-core/contracts/strategy/TrueFiStrategy.sol#L102-L103

In `TrueFiStrategy._deposit()` function, it called `stake()` on TrueMultiFarm. And in TrueMultiFarm, when calling `stake()`, it also claims reward for sender
```solidity
function stake(IERC20 token, uint256 amount) external override hasShares(token) update(token) {
    if (stakerRewards[token].claimableReward[msg.sender] > 0) {
        _claim(token);
    }
    stakes[token].staked[msg.sender] = stakes[token].staked[msg.sender].add(amount);
    stakes[token].totalStaked = stakes[token].totalStaked.add(amount);

    token.safeTransferFrom(msg.sender, address(this), amount);
    emit Stake(token, msg.sender, amount);
}
```

These reward token is not sent to `LIQUIDITY_MINING_RECEIVER` immediately but instead stay in TrueFiStrategy. It can make liquidity mining distribute reward with lower rate than expected.

## Impact
Claimed reward is not sent to liquidity mining immediately can make liquidity mining rate lower than expected.

## Tool used

Manual Review

## Recommendation

Consider send claimed reward immediately after calling `stake()`
