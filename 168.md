bin2chen

high

# claimCOMPAndTransfer() COMP may be locked into the contract

## Summary
Malicious users can keep front-run `claimCOMPAndTransfer() ` to trigger `COMPTROLLER.claimComp() ` first, causing `netBalance` in `claimCOMPAndTransfer() ` to be 0 all the time, resulting in `COMP` not being transferred out and locked in the contract
## Vulnerability Detail
`claimCOMPAndTransfer()` use for "Claims COMP incentives earned and transfers to the treasury manager contract"
The code is as follows:
```solidity
    function claimCOMPAndTransfer(address[] calldata cTokens)
        external
        override
        onlyManagerContract
        nonReentrant
        returns (uint256)
    {
        uint256 balanceBefore = COMP.balanceOf(address(this));
        COMPTROLLER.claimComp(address(this), cTokens);
        uint256 balanceAfter = COMP.balanceOf(address(this));

        // NOTE: the onlyManagerContract modifier prevents a transfer to address(0) here
        uint256 netBalance = balanceAfter.sub(balanceBefore);   //<-------@only transfer out `netBalance`
        if (netBalance > 0) {
            COMP.safeTransfer(msg.sender, netBalance);
        }

        // NOTE: TreasuryManager contract will emit a COMPHarvested event
        return netBalance;
```

From the above code, we can see that this method only turns out the difference value `netBalance`
But `COMPTROLLER.claimComp()` can be called by anyone, if there is a malicious user front-run this transcation to triggers `COMPTROLLER.claimComp()` first 
This will cause the`netBalance` to be 0 all the time, resulting in `COMP` not being transferred out and being locked in the contract.

The following code is from `Comptroller.sol`

https://github.com/compound-finance/compound-protocol/blob/master/contracts/Comptroller.sol

```solidity
    function claimComp(address holder, CToken[] memory cTokens) public { //<----------anyone can call it
        address[] memory holders = new address[](1);
        holders[0] = holder;
        claimComp(holders, cTokens, true, true);
    }
```

## Impact

`COMP ` may be locked into the contract

## Code Snippet

https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/external/actions/TreasuryAction.sol#L118C4-L123

## Tool used

Manual Review

## Recommendation

Transfer all balances, not using `netBalance`
