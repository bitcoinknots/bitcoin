Mining policy
-------------

- Coin-age priority selection now respects `blockmintxfee`, using modified
  fees and policy virtual size. Transactions below this floor can still be
  selected with fee-paying descendants through package selection. Setting
  the mining fee floor to zero permits transactions with zero modified fees;
  negative modified fees still need package sponsorship. This change does
  not alter relay policy defaults.
