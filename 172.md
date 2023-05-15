bin2chen

high

# repayAccountPrimeDebtAtSettlement() user lost residual cash

## Summary

in `repayAccountPrimeDebtAtSettlement() `
Incorrect calculation of `primeCashRefund` value (always == 0)
Resulting in the loss of the user's residual  cash

## Vulnerability Detail

when settle Vault Account 
will execute `settleVaultAccount()`->`repayAccountPrimeDebtAtSettlement()`
In the `repayAccountPrimeDebtAtSettlement()` method the residual amount will be refunded to the user
The code is as follows.
```solidity
    function repayAccountPrimeDebtAtSettlement(
        PrimeRate memory pr,
        VaultStateStorage storage primeVaultState,
        uint16 currencyId,
        address vault,
        address account,
        int256 accountPrimeCash,
        int256 accountPrimeStorageValue
    ) internal returns (int256 finalPrimeDebtStorageValue, bool didTransfer) {
...

            if (netPrimeDebtRepaid < accountPrimeStorageValue) {
                // If the net debt change is greater than the debt held by the account, then only
                // decrease the total prime debt by what is held by the account. The residual amount
                // will be refunded to the account via a direct transfer.
                netPrimeDebtChange = accountPrimeStorageValue;
                finalPrimeDebtStorageValue = 0;

                int256 primeCashRefund = pr.convertFromUnderlying(
                    pr.convertDebtStorageToUnderlying(netPrimeDebtChange.sub(accountPrimeStorageValue)) //<--------@audit always ==0
                );
                TokenHandler.withdrawPrimeCash(
                    account, currencyId, primeCashRefund, pr, false // ETH will be transferred natively
                );
                didTransfer = true;
            } else {
```

From the above code we can see that there is a spelling error

1. netPrimeDebtChange = accountPrimeStorageValue;
2. primeCashRefund = netPrimeDebtChange.sub(accountPrimeStorageValue)
so primeCashRefund always ==0

should be `primeCashRefund = netPrimeDebtRepaid - accountPrimeStorageValue`


## Impact

`primeCashRefund` always == 0 ,  user lost residual cash

## Code Snippet

https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/internal/vaults/VaultAccount.sol#L575


## Tool used

Manual Review

## Recommendation

```solidity
    function repayAccountPrimeDebtAtSettlement(
        PrimeRate memory pr,
        VaultStateStorage storage primeVaultState,
        uint16 currencyId,
        address vault,
        address account,
        int256 accountPrimeCash,
        int256 accountPrimeStorageValue
    ) internal returns (int256 finalPrimeDebtStorageValue, bool didTransfer) {
...

            if (netPrimeDebtRepaid < accountPrimeStorageValue) {
                // If the net debt change is greater than the debt held by the account, then only
                // decrease the total prime debt by what is held by the account. The residual amount
                // will be refunded to the account via a direct transfer.
                netPrimeDebtChange = accountPrimeStorageValue;
                finalPrimeDebtStorageValue = 0;

                int256 primeCashRefund = pr.convertFromUnderlying(
-                   pr.convertDebtStorageToUnderlying(netPrimeDebtChange.sub(accountPrimeStorageValue))
+                   pr.convertDebtStorageToUnderlying(netPrimeDebtRepaid.sub(accountPrimeStorageValue)) 
                );
                TokenHandler.withdrawPrimeCash(
                    account, currencyId, primeCashRefund, pr, false // ETH will be transferred natively
                );
                didTransfer = true;
            } else {
```

