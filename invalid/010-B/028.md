mstpr-brainbot

medium

# Lack of ERC20 approval on depositing to external money markets Compound V2

## Summary
Notional's current rebalancing process for depositing prime cash underlyings into Compound V2 generates the mint function without approval.
## Vulnerability Detail
Governance rebalances the prime cash underlyings by depositing them into various external money market platforms. Currently, Notional only supports Compound V2, for which an oracle and rebalancing strategy have been developed. When Compound V2 deposit call data is generated in the oracle, it only generates the cTokens' mint function without approval. However, it should first approve and then call the mint, as cToken takes the underlying from the Notional proxy and mints the cToken to the Notional proxy.

Upon careful examination of the v2 code, this finding passes tests because the old Notional V2 proxy already has approval for some Compound V2 cTokens. Since the Notional V2 code is not in scope for this contest and the approval situation is not mentioned in the protocol documentation, this finding should be considered valid. Furthermore, if the protocol wants to launch new cTokens for which V2 does not already have approval, the process will fail due to the lack of approval.
## Impact
This finding should be considered valid for several reasons:

The issue is not mentioned in the documentation provided by the protocol team. It is crucial for the documentation to be comprehensive, as it serves as a guide for developers and users to understand the intricacies of the protocol.
The Notional V2 code is out of scope for the contest. Therefore, the fact that the old Notional V2 proxy already has approval for some Compound V2 cTokens should not be considered a mitigating factor, as the focus should be on the current implementation and its potential issues.
Most importantly, this issue could impact the functionality of Notional when attempting to launch new cTokens for Compound V2 that do not already have an allowance in the proxy. The lack of approval would cause the process to fail, effectively limiting the growth and adaptability of the protocol.
In summary, this finding is valid due to its absence in the provided documentation, its relevance to the current implementation rather than the out-of-scope Notional V2 code, and its potential to limit the protocol's functionality when dealing with new cTokens for Compound V2. I'll call it as medium severity after all considerations.

It is important to note that this finding may not be applicable to non-implemented protocol oracles such as AAVE-Euler. In these cases, there is a possibility to create multiple call data deposits, allowing for a more flexible approach. Governance can first generate one call data to approve the required allowances and then generate a subsequent call data to initiate the deposit process.
## Code Snippet
https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/external/pCash/adapters/CompoundV2AssetAdapter.sol#L45-L48

## Tool used

Manual Review

## Recommendation
put a check on allowance before deposit something like this:

```solidity
if (IERC20.allowance(address(NotionalProxy), address(cToken))) {
      callData[0] = abi.encodeWithSelector(
        IERC20.approve.selector,
        address(NotionalProxy),
        address(cToken)
      );
    }
``` 