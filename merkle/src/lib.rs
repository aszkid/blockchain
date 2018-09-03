use std::cmp::Ordering;

/// Inmutable binary tree data structure.
///
#[derive(PartialEq, Debug)]
pub enum Tree<T> {
    Leaf {
        val: T,
        l: Box<Tree<T>>,
        r: Box<Tree<T>>
    },
    Empty
}

impl<T: Ord> Tree<T> {
    /// Create an empty binary tree.
    ///
    pub fn new() -> Tree<T> {
        Tree::Empty
    }

    /// Insert a new value recursively.
    ///
    pub fn insert(&mut self, nval: T) {
        match self {
            &mut Tree::Leaf { ref val, ref mut l, ref mut r } => {
                match nval.cmp(val) {
                    Ordering::Less => l.insert(nval),
                    Ordering::Greater => r.insert(nval),
                    _ => return
                }
            },
            &mut Tree::Empty => {
                *self = Tree::Leaf {
                    val: nval,
                    l: Box::new(Tree::Empty),
                    r: Box::new(Tree::Empty)
                }
            }
        }
    }

    /// Check whether the tree is Empty
    ///
    pub fn is_empty(&self) -> bool {
        match self {
            &Tree::Empty => true,
            &Tree::Leaf { .. } => false
        }
    }

    /// Find a value.
    ///
    pub fn find(&self, fval: T) -> Option<&Tree<T>> {
        match self {
            &Tree::Empty => None,
            &Tree::Leaf { ref val, ref l, ref r } => {
                match fval.cmp(val) {
                    Ordering::Less => l.find(fval),
                    Ordering::Greater => r.find(fval),
                    _ => Some(self)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_inserts() {
        // empty tree
        assert_eq!(
            Tree::<i64>::new(),
            Tree::Empty::<i64>
        );

        // integers
        let mut t1 = Tree::<i64>::new();
        t1.insert(9);
        assert_eq!(
            t1,
            Tree::Leaf { val: 9, l: Box::new(Tree::Empty), r: Box::new(Tree::Empty) }
        );

        t1.insert(4);
        assert_eq!(
            t1,
            Tree::Leaf {
                val: 9,
                l: Box::new(Tree::Leaf { val: 4, l: Box::new(Tree::Empty), r: Box::new(Tree::Empty) }),
                r: Box::new(Tree::Empty)
            }
        );

        t1.insert(5);
        assert_eq!(
            t1,
            Tree::Leaf {
                val: 9,
                l: Box::new(Tree::Leaf {
                                val: 4,
                                l: Box::new(Tree::Empty),
                                r: Box::new(Tree::Leaf { val: 5, l: Box::new(Tree::Empty), r: Box::new(Tree::Empty) })
                }),
                r: Box::new(Tree::Empty)
            }
        );
    }

    #[test]
    fn empty() {
        assert_eq!(
            Tree::<i64>::new().is_empty(),
            true
        );
        assert_eq!(
            Tree::Empty::<i64>.is_empty(),
            true
        );

        let mut t1 = Tree::<i64>::new();
        t1.insert(5);
        assert_eq!(
            t1.is_empty(),
            false
        );
    }

    #[test]
    fn find() {
        let mut t1 = Tree::<i64>::new();
        t1.insert(7);
        t1.insert(5);
        t1.insert(9);
        t1.insert(6);

        let t2 = Tree::Leaf {
            val: 5,
            l: Box::new(Tree::Empty),
            r: Box::new(Tree::Leaf {
                val: 6,
                l: Box::new(Tree::Empty),
                r: Box::new(Tree::Empty)
            })
        };

        assert_eq!(
            match t1.find(5) {
                Some(node) => node,
                _ => &Tree::Empty
            },
            &t2
        );

        assert_eq!(
            match t1.find(3) {
                Some(node) => node,
                _ => &Tree::Empty
            },
            &Tree::Empty
        );
    }
}
