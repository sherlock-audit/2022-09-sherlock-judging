Lambda

high

# TrueFiStrategy: Too little withdrawn when used with AlphaBetaSplitter

## Summary
`AlphaBetaSplitter` implicitly assumes that `withdrawAll` returns the whole balance, which is not true for `TrueFiStrategy`.

## Vulnerability Detail
When `_amount` is withdrawn from `AlphaBetaSplitter` and this value is larger than the balance of the first child (which was retrieved earlier with a `_balanceOf` call on the child), `withdrawAll` is called. Then, `_amount - childOneBalance` is withdrawn on the second child. This assumes that the `withdrawAll()` call on the first child in fact returned `childOneBalance`, i.e. the whole balance. However, this is not necessarily true for `TrueFiStrategy`. This strategy only returns the USDC that are currently held in the contract, whereas `_balanceOf()` returns the amount that is locked in TrueFi (but where a call to `liquidExit` is necessary to get the USDC into the strategy).

## Impact
Because of this issue, it can happen that significantly less tokens are returned than requested when TrueFi is used within an `AlphaBetaSplitter`. Let's say that 950,000 USDC are locked in TrueFi and 50,000 USDC are currently in the `TrueFiStrategy` contract. We assume that the `TrueFiStrategy` is the first child of an `AlphaBetaSplitter` and `_withdraw` is called with 1,000,050 USDC. Then, only 50,000 USDC (from TrueFi) + 50,000 USDC (from the second child) will be transferred to core, i.e. 100,000 USDC instead of 1,000,050 USDC.

## Code Snippet
https://github.com/sherlock-audit/2022-09-sherlock/blob/main/sherlock-v2-core/contracts/strategy/splitters/AlphaBetaSplitter.sol#L38
https://github.com/sherlock-audit/2022-09-sherlock/blob/main/sherlock-v2-core/contracts/strategy/TrueFiStrategy.sol#L111
https://github.com/sherlock-audit/2022-09-sherlock/blob/main/sherlock-v2-core/contracts/strategy/TrueFiStrategy.sol#L134

## Tool used

Manual Review

## Recommendation
Check the actual amount that was returned by `_withdrawAll` in `AlphaBetaSplitter`. This value is already returned by all strategies, so refactoring the Splitter to incorporate it should be easy.