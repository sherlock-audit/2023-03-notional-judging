xiaoming90

medium

# A single external protocol can DOS rebalancing process

## Summary

A failure in an external money market can DOS the entire rebalance process in Notional.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/external/pCash/ProportionalRebalancingStrategy.sol#L23

```solidity
File: ProportionalRebalancingStrategy.sol
23:     function calculateRebalance(
24:         IPrimeCashHoldingsOracle oracle,
25:         uint8[] calldata rebalancingTargets
26:     ) external view override onlyNotional returns (RebalancingData memory rebalancingData) {
27:         address[] memory holdings = oracle.holdings();
..SNIP..
40:         for (uint256 i; i < holdings.length;) {
41:             address holding = holdings[i];
42:             uint256 targetAmount = totalValue * rebalancingTargets[i] / uint256(Constants.PERCENTAGE_DECIMALS);
43:             uint256 currentAmount = values[i];
44: 
45:             redeemHoldings[i] = holding;
46:             depositHoldings[i] = holding;
..SNIP..
61:         }
62: 
63:         rebalancingData.redeemData = oracle.getRedemptionCalldataForRebalancing(redeemHoldings, redeemAmounts);
64:         rebalancingData.depositData = oracle.getDepositCalldataForRebalancing(depositHoldings, depositAmounts);
65:     }
```

During a rebalance, the `ProportionalRebalancingStrategy` will loop through all the holdings and perform a deposit or redemption against the external market of the holdings.

Assume that Notional integrates with four (4) external money markets (Aave V2, Aave V3, Compound V3, Morpho). In this case, whenever a rebalance is executed, Notional will interact with all four external money markets.

https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/external/actions/TreasuryAction.sol#L304

```solidity
File: TreasuryAction.sol
304:     function _executeDeposits(Token memory underlyingToken, DepositData[] memory deposits) private {
..SNIP..
316:             for (uint256 j; j < depositData.targets.length; ++j) {
317:                 // This will revert if the individual call reverts.
318:                 GenericToken.executeLowLevelCall(
319:                     depositData.targets[j], 
320:                     depositData.msgValue[j], 
321:                     depositData.callData[j]
322:                 );
323:             }
```

https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/internal/balances/TokenHandler.sol#L357

```solidity
File: TokenHandler.sol
357:     function executeMoneyMarketRedemptions(
..SNIP..
373:             for (uint256 j; j < data.targets.length; j++) {
374:                 // This will revert if the individual call reverts.
375:                 GenericToken.executeLowLevelCall(data.targets[j], 0, data.callData[j]);
376:             }
```

However, as long as one external money market reverts, the entire rebalance process will be reverted and Notional would not be able to rebalance its underlying assets.

The call to the external money market can revert due to many reasons, which include the following:

- Changes in the external protocol's interfaces (e.g. function signatures modified or functions added or removed)
- The external protocol is paused
- The external protocol has been compromised
- The external protocol suffers from an upgrade failure causing an error in the new contract code.

## Impact

Notional would not be able to rebalance its underlying holding if one of the external money markets causes a revert. The probability of this issue occurring increases whenever Notional integrates with a new external money market

The key feature of Notional V3 is to allow its Treasury Manager to rebalance underlying holdings into various other money market protocols. 

This makes Notional more resilient to issues in external protocols and future-proofs the protocol. If rebalancing does not work, Notional will be unable to move its fund out of a vulnerable external market, potentially draining protocol funds if this is not mitigated.

Another purpose of rebalancing is to allow Notional to allocate Notional V3’s capital to new opportunities or protocols that provide a good return. If rebalancing does not work, the protocol and its users will lose out on the gain from the investment.

On the other hand, if an external monkey market that Notional invested in is consistently underperforming or yielding negative returns, Notional will perform a rebalance to reallocate its funds to a better market. However, if rebalancing does not work, they will be stuck with a suboptimal asset allocation, and the protocol and its users will incur losses.

## Code Snippet

https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/external/pCash/ProportionalRebalancingStrategy.sol#L23

https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/external/actions/TreasuryAction.sol#L304

https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/internal/balances/TokenHandler.sol#L357

## Tool used

Manual Review

## Recommendation

Consider implementing a more resilient rebalancing process that allows for failures in individual external money markets. For instance, Notional could catch reverts from individual money markets and continue the rebalancing process with the remaining markets. 