// merkle tree setting
pub(crate) const N_LEAFS: usize = 8;
pub(crate) const PATH_LEN: usize = N_LEAFS.trailing_zeros() as usize;
pub(crate) const TREE_LAYERS: usize = PATH_LEN + 1;

// constraint system matrix setting
pub(crate) const N_ROWS_USED: usize = 2 * PATH_LEN;
pub(crate) const LAST_ROW: usize = N_ROWS_USED - 1;
