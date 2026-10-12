/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

// Ported from Apple Libc's stdlib/FreeBSD/qsort.c and heapsort.c.

//! The `qsort(3)` upstream sorts its path tables with. Its comparisons
//! call distinct directories equal (they only look at the name before the
//! last dot), and libc's quicksort is not stable, so the order of equal
//! entries is whatever this algorithm leaves. This is macOS's: Bentley &
//! McIlroy's "Engineering a Sort Function" with an insertion-sort cutoff
//! and a heapsort fallback past the recursion limit.

use std::cmp::min;

/// `qsort` of `a` by `cmp`, element for element as macOS orders it.
pub(super) fn qsort<T: Copy>(a: &mut [T], cmp: &mut impl FnMut(T, T) -> i32) {
    let n = a.len();
    // DEPTH(x): 2 * (flsl(x) - 1).
    let depth = 2 * (usize::BITS as i32 - n.leading_zeros() as i32 - 1);
    sort(a, cmp, depth);
}

/// Simple insertion sort routine. False if it gave up after `swap_limit`
/// swaps (0 for no limit).
fn isort<T: Copy>(a: &mut [T], cmp: &mut impl FnMut(T, T) -> i32, swap_limit: usize) -> bool {
    let mut swap_cnt = 0;
    for pm in 1..a.len() {
        let mut pl = pm;
        while pl > 0 && cmp(a[pl - 1], a[pl]) > 0 {
            a.swap(pl, pl - 1);
            swap_cnt += 1;
            if swap_limit != 0 && swap_cnt > swap_limit {
                return false;
            }
            pl -= 1;
        }
    }
    true
}

/// Find the median of 3 elements.
fn med3<T: Copy>(
    a: &[T],
    x: usize,
    y: usize,
    z: usize,
    cmp: &mut impl FnMut(T, T) -> i32,
) -> usize {
    if cmp(a[x], a[y]) < 0 {
        if cmp(a[y], a[z]) < 0 {
            y
        } else if cmp(a[x], a[z]) < 0 {
            z
        } else {
            x
        }
    } else if cmp(a[y], a[z]) > 0 {
        y
    } else if cmp(a[x], a[z]) < 0 {
        x
    } else {
        z
    }
}

fn vecswap<T: Copy>(a: &mut [T], x: usize, y: usize, n: usize) {
    for i in 0..n {
        a.swap(x + i, y + i);
    }
}

fn sort<T: Copy>(mut a: &mut [T], cmp: &mut impl FnMut(T, T) -> i32, mut depth_limit: i32) {
    loop {
        let n = a.len();
        let mut swap_cnt = false;

        if depth_limit <= 0 {
            // We've hit our recursion limit, switch to heapsort
            heapsort(a, cmp);
            return;
        }
        depth_limit -= 1;

        if n <= 7 {
            // For sufficiently small inputs, we'll just insertion sort.
            isort(a, cmp, 0);
            return;
        }

        // Compute the pseudomedian. Small arrays use 3 samples, large ones
        // use 9.
        let mut pl = 0;
        let mut pm = n / 2;
        let mut pn = n - 1;
        if n > 40 {
            let d = n / 8;
            pl = med3(a, pl, pl + d, pl + 2 * d, cmp);
            pm = med3(a, pm - d, pm, pm + d, cmp);
            pn = med3(a, pn - 2 * d, pn - d, pn, cmp);
        }
        pm = med3(a, pl, pm, pn, cmp);

        // Pull the median to the front.
        a.swap(0, pm);
        let (mut pa, mut pb) = (1, 1);
        let (mut pc, mut pd) = (n as isize - 1, n - 1);

        loop {
            // - Move b forward while it's less than the median
            // - Move c backwards while it's greater than the median
            // - When equal to the median, swap to the outside
            while pb as isize <= pc {
                let r = cmp(a[pb], a[0]);
                if r > 0 {
                    break;
                }
                if r == 0 {
                    swap_cnt = true;
                    a.swap(pa, pb);
                    pa += 1;
                }
                pb += 1;
            }
            while pb as isize <= pc {
                let c = pc as usize;
                let r = cmp(a[c], a[0]);
                if r < 0 {
                    break;
                }
                if r == 0 {
                    swap_cnt = true;
                    a.swap(c, pd);
                    pd -= 1;
                }
                pc -= 1;
            }
            if pb as isize > pc {
                break;
            }
            a.swap(pb, pc as usize);
            swap_cnt = true;
            pb += 1;
            pc -= 1;
        }

        // So swap the '=' into the middle. pc never drops below pb - 1.
        let pc = pc as usize;
        let d1 = min(pa, pb - pa);
        vecswap(a, 0, pb - d1, d1);
        let d1 = min(pd - pc, n - pd - 1);
        vecswap(a, pb, n - d1, d1);

        if !swap_cnt {
            // Switch to insertion sort
            let r = 1 + n / 4;
            if isort(a, cmp, r) {
                return;
            }
        }

        let d1 = pb - pa;
        let d2 = pd - pc;
        if d1 <= d2 {
            // Recurse on left partition, then iterate on right partition
            if d1 > 1 {
                sort(&mut a[..d1], cmp, depth_limit);
            }
            if d2 <= 1 {
                return;
            }
            a = &mut a[n - d2..];
        } else {
            // Recurse on right partition, then iterate on left partition
            if d2 > 1 {
                sort(&mut a[n - d2..], cmp, depth_limit);
            }
            if d1 <= 1 {
                return;
            }
            a = &mut a[..d1];
        }
    }
}

/// Heapsort -- Knuth, Vol. 3, page 145, with the elements numbered from 1.
fn heapsort<T: Copy>(a: &mut [T], cmp: &mut impl FnMut(T, T) -> i32) {
    let mut nmemb = a.len();
    if nmemb <= 1 {
        return;
    }
    // Build the list into a heap, where a heap is defined such that for
    // the records K1 ... KN, Kj/2 >= Kj for 1 <= j/2 <= j <= N.
    for l in (1..=nmemb / 2).rev() {
        let mut par_i = l;
        loop {
            let mut child_i = par_i * 2;
            if child_i > nmemb {
                break;
            }
            if child_i < nmemb && cmp(a[child_i - 1], a[child_i]) < 0 {
                child_i += 1;
            }
            if cmp(a[child_i - 1], a[par_i - 1]) <= 0 {
                break;
            }
            a.swap(par_i - 1, child_i - 1);
            par_i = child_i;
        }
    }
    // For each element of the heap, save the largest element into its
    // final slot, save the displaced element (k), then recreate the heap.
    while nmemb > 1 {
        let k = a[nmemb - 1];
        a[nmemb - 1] = a[0];
        nmemb -= 1;
        let mut par_i = 1;
        loop {
            let mut child_i = par_i * 2;
            if child_i > nmemb {
                break;
            }
            if child_i < nmemb && cmp(a[child_i - 1], a[child_i]) < 0 {
                child_i += 1;
            }
            a[par_i - 1] = a[child_i - 1];
            par_i = child_i;
        }
        loop {
            let child_i = par_i;
            par_i = child_i / 2;
            if child_i == 1 || cmp(k, a[par_i - 1]) < 0 {
                a[child_i - 1] = k;
                break;
            }
            a[child_i - 1] = a[par_i - 1];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_and_matches_macos_order_of_equal_elements() {
        // Thirty directories that all compare equal, in the order bsdtar
        // added them, and the order macOS's qsort leaves them in.
        let input = [
            1, 6, 8, 9, 7, 26, 19, 21, 17, 28, 10, 11, 16, 29, 20, 27, 18, 5, 2, 3, 4, 22, 25, 13,
            14, 15, 12, 24, 23, 30,
        ];
        let expect = [
            30, 6, 8, 9, 7, 26, 19, 21, 17, 28, 10, 11, 16, 29, 20, 27, 18, 5, 2, 3, 4, 22, 25, 13,
            14, 15, 12, 24, 23, 1,
        ];
        let mut a = input;
        qsort(&mut a, &mut |_, _| 0);
        assert_eq!(a, expect);

        for n in [0, 1, 2, 7, 8, 40, 41, 100, 1000] {
            let mut v: Vec<i64> = (0..n).map(|i| (i * 7919 + 13) % 101).collect();
            let mut w = v.clone();
            qsort(&mut v, &mut |x, y| (x - y) as i32);
            w.sort();
            assert_eq!(v, w);
            heapsort(&mut w, &mut |x, y| (y - x) as i32);
            assert!(w.windows(2).all(|p| p[0] >= p[1]));
        }
    }
}
