xiaoming90

high

# Vaults can avoid liquidations by not letting their vault account be settled

## Summary

Vault liquidations will leave un-matured accounts with cash holdings which are then used to offset account debt during vault account settlements. As it stands, any excess cash received via interest accrual will be transferred back to the vault account directly. If a primary or secondary borrow currency is `ETH`, then this excess cash will be transferred natively. Consequently, the recipient may intentionally revert, causing account settlement to fail. 

## Vulnerability Detail

The issue arises in the `VaultAccount.repayAccountPrimeDebtAtSettlement()` function. If there is any excess cash due to interest accrual, then this amount will be refunded to the vault account. Native `ETH` is not wrapped when it should be wrapped, allowing the recipient to take control over the flow of execution.

https://github.com/sherlock-audit/2023-03-notional-0xleastwood/blob/main/contracts-v2/contracts/internal/vaults/VaultAccount.sol#L548-L596

```solidity
File: VaultAccount.sol
548:     function repayAccountPrimeDebtAtSettlement(
549:         PrimeRate memory pr,
550:         VaultStateStorage storage primeVaultState,
551:         uint16 currencyId,
552:         address vault,
553:         address account,
554:         int256 accountPrimeCash,
555:         int256 accountPrimeStorageValue
556:     ) internal returns (int256 finalPrimeDebtStorageValue, bool didTransfer) {
557:         didTransfer = false;
558:         finalPrimeDebtStorageValue = accountPrimeStorageValue;
559:         
560:         if (accountPrimeCash > 0) {
561:             // netPrimeDebtRepaid is a negative number
562:             int256 netPrimeDebtRepaid = pr.convertUnderlyingToDebtStorage(
563:                 pr.convertToUnderlying(accountPrimeCash).neg()
564:             );
565: 
566:             int256 netPrimeDebtChange;
567:             if (netPrimeDebtRepaid < accountPrimeStorageValue) {
568:                 // If the net debt change is greater than the debt held by the account, then only
569:                 // decrease the total prime debt by what is held by the account. The residual amount
570:                 // will be refunded to the account via a direct transfer.
571:                 netPrimeDebtChange = accountPrimeStorageValue;
572:                 finalPrimeDebtStorageValue = 0;
573: 
574:                 int256 primeCashRefund = pr.convertFromUnderlying(
575:                     pr.convertDebtStorageToUnderlying(netPrimeDebtChange.sub(accountPrimeStorageValue))
576:                 );
577:                 TokenHandler.withdrawPrimeCash(
578:                     account, currencyId, primeCashRefund, pr, false // ETH will be transferred natively
579:                 );
580:                 didTransfer = true;
581:             } else {
582:                 // In this case, part of the account's debt is repaid.
583:                 netPrimeDebtChange = netPrimeDebtRepaid;
584:                 finalPrimeDebtStorageValue = accountPrimeStorageValue.sub(netPrimeDebtRepaid);
585:             }
586: 
587:             // Updates the global prime debt figure and events are emitted via the vault.
588:             pr.updateTotalPrimeDebt(vault, currencyId, netPrimeDebtChange);
589: 
590:             // Updates the state on the prime vault storage directly.
591:             int256 totalPrimeDebt = int256(uint256(primeVaultState.totalDebt));
592:             int256 newTotalDebt = totalPrimeDebt.add(netPrimeDebtChange);
593:             // Set the total debt to the storage value
594:             primeVaultState.totalDebt = newTotalDebt.toUint().toUint80();
595:         }
596:     }
```

As seen here, a `withdrawWrappedNativeToken` is used to signify when a native `ETH` transfer will be wrapped before sending an amount. In the case of vault settlement, this is always sent to `false`.

https://github.com/sherlock-audit/2023-03-notional-0xleastwood/blob/main/contracts-v2/contracts/internal/balances/TokenHandler.sol#L220-L247

```solidity
File: TokenHandler.sol
220:     function withdrawPrimeCash(
221:         address account,
222:         uint16 currencyId,
223:         int256 primeCashToWithdraw,
224:         PrimeRate memory primeRate,
225:         bool withdrawWrappedNativeToken
226:     ) internal returns (int256 netTransferExternal) {
227:         if (primeCashToWithdraw == 0) return 0;
228:         require(primeCashToWithdraw < 0);
229: 
230:         Token memory underlying = getUnderlyingToken(currencyId);
231:         netTransferExternal = convertToExternal(
232:             underlying, 
233:             primeRate.convertToUnderlying(primeCashToWithdraw) 
234:         );
235: 
236:         // Overflow not possible due to int256
237:         uint256 withdrawAmount = uint256(netTransferExternal.neg());
238:         _redeemMoneyMarketIfRequired(currencyId, underlying, withdrawAmount);
239: 
240:         if (underlying.tokenType == TokenType.Ether) {
241:             GenericToken.transferNativeTokenOut(account, withdrawAmount, withdrawWrappedNativeToken);
242:         } else {
243:             GenericToken.safeTransferOut(underlying.tokenAddress, account, withdrawAmount);
244:         }
245: 
246:         _postTransferPrimeCashUpdate(account, currencyId, netTransferExternal, underlying, primeRate);
247:     }
```

It's likely that the vault account is considered solvent in this case, but due to the inability to trade between currencies, it is not possible to use excess cash in one currency to offset debt in another.

## Impact

Liquidations require vaults to be settled if `block.timestamp` is past the maturity date, hence, it is not possible to deleverage vault accounts, leading to bad debt accrual.

## Code Snippet

https://github.com/sherlock-audit/2023-03-notional-0xleastwood/blob/main/contracts-v2/contracts/internal/vaults/VaultAccount.sol#L548-L596

https://github.com/sherlock-audit/2023-03-notional-0xleastwood/blob/main/contracts-v2/contracts/internal/balances/TokenHandler.sol#L220-L247

## Tool used

Manual Review

## Recommendation

Consider wrapping `ETH` under all circumstances. This will prevent vault accounts from intentionally reverting and preventing their account from being settled.