PRAISE

medium

# The address of `owner`, `pauseRouter_`, `pauseGaurdian_` can't be updated via the initialize() function during future L2 redeployments because the constructor sets `hasInitialized` to true.

## Summary
The address of `owner`, `pauseRouter_`, `pauseGaurdian_` can't be updated via the initialize() function because the constructor sets `hasInitialized` flag to true.

## Vulnerability Detail
The constructor sets the `hasInitialized` flag to true as soon as the contract is deployed, which effectively locks the contract in its assumed initialized state. But, the address of `owner`, `pauseRouter_` and  `pauseGuardian_` weren't updated in constructor, the devs want to update them via the initialize() function. 
This won't be possible because the initialize() function checks and requires that `hasInitialized` flag must be false before the function can be called. In Router.sol's case the constructor sets the `hasInitialized` flag to true making it impossible to update `owner`, `pauseRouter_` and `pauseGaurdian_`. This is critical as this contract `Router.sol` won't have these roles set.

i spoke with one of the Devs and he said "the `initialize() function` method is mainly left there for future L2 deployments". But i still insist to submit this because since the constructor sets `hasInitialized` flag to `true`, the initialize() function can't be called due to this require statement
```solidity
        require(msg.sender == DEPLOYER && !hasInitialized);
```  
pls take note of `!hasInitialized` in the above require statement.

Even in future L2 deployments the Devs won't be able to use the initialize() function unless they'll have to redeploy the router.sol and set the `hasInitialized` flag to false in the constructor. 

## Impact
Router.sol won't have `owner`, `pauseRouter_` and `pauseGaurdian_` roles set up during future L2 deployments
Contracts that inherit the Router.sol and try to use these roles will have issues. 
## Code Snippet
https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/external/Router.sol#L66-L88

https://github.com/sherlock-audit/2023-03-notional/blob/main/contracts-v2/contracts/external/Router.sol#L90-L100
## Tool used

Manual Review

## Recommendation
set `hasInitialized` flag to false in the constructor since the contract isn't fully initialized, to make it possible to update `owner`, `pauseRouter_` and `pauseGaurdian_`  via the initialize() function and THEN IMPLEMENT ACCESS CONTROL ON THE `initialize()` function WITH MAYBE AN `ONLYOWNER` MODIFIER OR A REQUIRE STATEMENT.