xiaoming90

medium

# It may be possible to liquidate on behalf of another account

## Summary

If the caller of any liquidation action is the vault itself, there is no validation of the `liquidator` parameter and therefore, any arbitrary account may act as the liquidator if they have approved any amount of funds for the `VaultLiquidationAction.sol` contract.

## Vulnerability Detail

While the vault implementation itself should most likely handle proper validation of the parameters provided to actions enabled by the vault, the majority of important validation should be done within the Notional protocol. The base implementation for vaults does not seem to sanitise `liquidator` and hence users could deleverage accounts on behalf of a liquidator which has approved Notional's contracts.

https://github.com/sherlock-audit/2023-03-notional-0xleastwood/blob/main/contracts-v2/contracts/external/actions/VaultLiquidationAction.sol#L197-L237

```solidity
File: VaultLiquidationAction.sol
197:     function _authenticateDeleverage(
198:         address account,
199:         address vault,
200:         address liquidator
201:     ) private returns (
202:         VaultConfig memory vaultConfig,
203:         VaultAccount memory vaultAccount,
204:         VaultState memory vaultState
205:     ) {
206:         // Do not allow invalid accounts to liquidate
207:         requireValidAccount(liquidator);
208:         require(liquidator != vault);
209: 
210:         // Cannot liquidate self, if a vault needs to deleverage itself as a whole it has other methods 
211:         // in VaultAction to do so.
212:         require(account != msg.sender);
213:         require(account != liquidator);
214: 
215:         vaultConfig = VaultConfiguration.getVaultConfigStateful(vault);
216:         require(vaultConfig.getFlag(VaultConfiguration.DISABLE_DELEVERAGE) == false);
217: 
218:         // Authorization rules for deleveraging
219:         if (vaultConfig.getFlag(VaultConfiguration.ONLY_VAULT_DELEVERAGE)) {
220:             require(msg.sender == vault);
221:         } else {
222:             require(msg.sender == liquidator);
223:         }
224: 
225:         vaultAccount = VaultAccountLib.getVaultAccount(account, vaultConfig);
226: 
227:         // Vault accounts that are not settled must be settled first by calling settleVaultAccount
228:         // before liquidation. settleVaultAccount is not permissioned so anyone may settle the account.
229:         require(block.timestamp < vaultAccount.maturity, "Must Settle");
230: 
231:         if (vaultAccount.maturity == Constants.PRIME_CASH_VAULT_MATURITY) {
232:             // Returns the updated prime vault state
233:             vaultState = vaultAccount.accruePrimeCashFeesToDebtInLiquidation(vaultConfig);
234:         } else {
235:             vaultState = VaultStateLib.getVaultState(vaultConfig, vaultAccount.maturity);
236:         }
237:     }
```

## Impact

A user may be forced to liquidate an account they do not wish to purchase vault shares for.

## Code Snippet

https://github.com/notional-finance/leveraged-vaults/blob/master/contracts/vaults/BaseStrategyVault.sol#L204-L216

## Tool used

Manual Review

## Recommendation

Make the necessary changes to `BaseStrategyVault.sol` or `_authenticateDeleverage()`, whichever is preferred.