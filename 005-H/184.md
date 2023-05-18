xiaoming90

high

# StrategyVault can perform a full exit without repaying all secondary debt

## Summary

StrategyVault can perform a full exit without repaying all secondary debt, leaving bad debt with the protocol.

## Vulnerability Detail

Noted from the [codebase's comment](https://github.com/notional-finance/contracts-v2/blob/63eb0b46ec37e5fc5447bdde3d951dd90f245741/contracts/external/actions/VaultAction.sol#L61) that:

> Vaults can borrow up to the capacity using the `borrowSecondaryCurrencyToVault` and `repaySecondaryCurrencyToVault` methods. Vaults that use a secondary currency must ALWAYS repay the secondary debt during redemption and handle accounting for the secondary currency themselves.

Thus, when the StrategyVault-side performs a full exit for a vault account, Notional-side does not check that all secondary debts of that vault account are cleared (= zero) and will simply trust StrategyVault-side has already handled them properly.

Line 271 below shows that only validates the primary debt but not the secondary debt during a full exit.

https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/external/actions/VaultAccountAction.sol#L271

```solidity
File: VaultAccountAction.sol
271:         if (vaultAccount.accountDebtUnderlying == 0 && vaultAccount.vaultShares == 0) {
272:             // If the account has no position in the vault at this point, set the maturity to zero as well
273:             vaultAccount.maturity = 0;
274:         }
275:         vaultAccount.setVaultAccount({vaultConfig: vaultConfig, checkMinBorrow: true});
276: 
277:         // It's possible that the user redeems more vault shares than they lend (it is not always the case
278:         // that they will be increasing their collateral ratio here, so we check that this is the case). No
279:         // need to check if the account has exited in full (maturity == 0).
280:         if (vaultAccount.maturity != 0) {
281:             IVaultAccountHealth(address(this)).checkVaultAccountCollateralRatio(vault, account);
282:         }
```

## Impact

Leveraged vaults are designed to be as isolated as possible to mitigate the risk to the Notional protocol and its users. However, the above implementation seems to break this principle. As such, if there is a vulnerability in the leverage vault that allows someone to exploit this issue and bypass the repayment of the secondary debt, the protocol will be left with a bad debt which affects the insolvency of the protocol.

## Code Snippet

https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/external/actions/VaultAccountAction.sol#L271

## Tool used

Manual Review

## Recommendation

Consider checking that all secondary debts of a vault account are cleared before executing a full exit.

```diff
+ int256 accountDebtOne;
+ int256 accountDebtTwo;

+ if (vaultConfig.hasSecondaryBorrows()) {
+ 	(/* */, accountDebtOne, accountDebtTwo) = VaultSecondaryBorrow.getAccountSecondaryDebt(vaultConfig, account, pr);
+ }

- if (vaultAccount.accountDebtUnderlying == 0 && vaultAccount.vaultShares == 0) {
+ if (vaultAccount.accountDebtUnderlying == 0 && vaultAccount.vaultShares == 0 && accountDebtOne == 0 && accountDebtTwo == 0) {
	// If the account has no position in the vault at this point, set the maturity to zero as well
	vaultAccount.maturity = 0;
}
vaultAccount.setVaultAccount({vaultConfig: vaultConfig, checkMinBorrow: true});
```