# Pedersen hash description

$H: (D, M) \rightarrow Z_r$,

where $D \in [0, 63]$ is some kind of salt, $M$ is message.

## Computation

1. Concat bitmask of D and M and split it with triplets
2. for each triplet compute $(1-2 b_2)(2 + 2 b_0 + b_1)$ and multiply to subgroup generator, depending from number of current triplet
3. sum all points and return X coordinate of resulting point