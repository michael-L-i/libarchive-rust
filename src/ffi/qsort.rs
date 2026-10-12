//! Use the platform's ordering of ties, as upstream's path tables do.

use crate::util::Error;
use std::cell::Cell;
use std::ffi::{c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

struct Element<'a, T, F> {
    value: T,
    compare: &'a F,
    panicked: &'a Cell<bool>,
}

extern "C" fn compare<T: Copy, F: Fn(T, T) -> i32>(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: qsort only passes aligned pointers to initialized elements of
    // the array supplied below. It has exclusive access to the array and
    // moves whole elements; the referenced comparator and flag stay live.
    let (a, b) = unsafe {
        (
            &*a.cast::<Element<'_, T, F>>(),
            &*b.cast::<Element<'_, T, F>>(),
        )
    };
    if a.panicked.get() {
        return 0;
    }
    match catch_unwind(AssertUnwindSafe(|| (a.compare)(a.value, b.value))) {
        Ok(order) => order,
        Err(payload) => {
            // A panic payload may itself panic when dropped.
            std::mem::forget(payload);
            a.panicked.set(true);
            0
        }
    }
}

/// Sort Copy values without a global callback or platform-specific qsort_r.
/// A comparator panic becomes an error after qsort returns; the input is
/// only updated on success.
pub(crate) fn qsort<T: Copy, F: Fn(T, T) -> i32>(
    values: &mut [T],
    compare_values: F,
) -> Result<(), Error> {
    if values.len() < 2 {
        return Ok(());
    }
    let panicked = Cell::new(false);
    let mut elements = Vec::new();
    elements
        .try_reserve_exact(values.len())
        .map_err(|_| Error::fatal(libc::ENOMEM, "Can't allocate memory"))?;
    for &value in values.iter() {
        elements.push(Element {
            value,
            compare: &compare_values,
            panicked: &panicked,
        });
    }
    // SAFETY: elements is a writable array of len initialized elements.
    // The Copy values and shared references can be relocated bytewise.
    // The callback neither mutates the array nor unwinds across the ABI.
    unsafe {
        libc::qsort(
            elements.as_mut_ptr().cast(),
            elements.len(),
            size_of_val(&elements[0]),
            Some(compare::<T, F>),
        );
    }
    if panicked.get() {
        return Err(Error::fatal(libc::EINVAL, "Path table comparator panicked"));
    }
    for (value, element) in values.iter_mut().zip(elements) {
        *value = element.value;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_reentrant_sorts() {
        assert!(qsort::<u8, _>(&mut [], |a, b| i32::from(a) - i32::from(b)).is_ok());
        let mut values = [3, 1, 2];
        assert!(
            qsort(&mut values, |a, b| {
                let mut inner = [2, 1];
                assert!(qsort(&mut inner, |a, b| a - b).is_ok());
                assert_eq!(inner, [1, 2]);
                a - b
            })
            .is_ok()
        );
        assert_eq!(values, [1, 2, 3]);
    }

    #[test]
    fn a_panicking_comparator_does_not_unwind_into_libc() {
        let mut values = [2, 1];
        assert!(qsort(&mut values, |_, _| panic!("comparator")).is_err());
        assert_eq!(values, [2, 1]);
    }
}
