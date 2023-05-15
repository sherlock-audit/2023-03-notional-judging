xiaoming90

medium

# Return data from the external call not verified during deposit and redemption

## Summary

The [deposit](https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/external/actions/TreasuryAction.sol#L318) and [redemption](https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/internal/balances/TokenHandler.sol#L375) functions did not verify the return data from the external call, which might cause the contract to wrongly assume that the deposit/redemption went well although the action has actually failed in the background.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/internal/balances/protocols/GenericToken.sol#L63

```solidity
File: GenericToken.sol
63:     function executeLowLevelCall(
64:         address target,
65:         uint256 msgValue,
66:         bytes memory callData
67:     ) internal {
68:         (bool status, bytes memory returnData) = target.call{value: msgValue}(callData);
69:         require(status, checkRevertMessage(returnData));
70:     }
```

When the external call within the `GenericToken.executeLowLevelCall` function reverts, the `status` returned from the `.call` will be `false`. In this case, Line 69 above will revert.

https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/internal/balances/TokenHandler.sol#L375

```solidity
File: TreasuryAction.sol
316:             for (uint256 j; j < depositData.targets.length; ++j) {
317:                 // This will revert if the individual call reverts.
318:                 GenericToken.executeLowLevelCall(
319:                     depositData.targets[j], 
320:                     depositData.msgValue[j], 
321:                     depositData.callData[j]
322:                 );
323:             }
```

For deposit and redeem, Notional assumes that all money markets will revert if the deposit/mint and redeem/burn has an error. Thus, it does not verify the return data from the external call. Refer to the comment in Line 317 above.

However, this is not always true due to the following reasons:

- Some money markets might not revert when errors occur but instead return `false (0)`. In this case, the current codebase will wrongly assume that the deposit/redemption went well although the action has failed.
- Compound might upgrade its contracts to return errors instead of reverting in the future.

## Impact

The gist of prime cash is to integrate with multiple markets. Thus, the codebase should be written in a manner that can handle multiple markets. Otherwise, the contract will wrongly assume that the deposit/redemption went well although the action has actually failed in the background, which might potentially lead to some edge cases where assets are sent to the users even though the redemption fails.

## Code Snippet

https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/internal/balances/TokenHandler.sol#L375

https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/external/actions/TreasuryAction.sol#L318

## Tool used

Manual Review

## Recommendation

Consider checking the `returnData` to ensure that the external money market returns a successful response after deposit and redemption. 

Note that the successful response returned from various money markets might be different. Some protocols return `1` on a successful action, while Compound return zero (`NO_ERROR`).