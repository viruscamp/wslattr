pub trait VecPushGetMut<T> {
    fn push_get_mut(&mut self, value: T) -> &mut T;
    fn find_or_push(&mut self, cond: impl Fn(&T) -> bool, get_val: impl FnOnce() -> T)-> &mut T;
}

impl<T> VecPushGetMut<T> for Vec<T> {
    fn push_get_mut(&mut self, value: T) -> &mut T {
        self.push(value);
        self.last_mut().unwrap()
    }

    fn find_or_push(&mut self, cond: impl Fn(&T) -> bool, get_val: impl FnOnce() -> T) -> &mut T {
        let idx = self.iter().enumerate()
            .find(|e| cond(e.1))
            .map(|e| e.0);
        if let Some(i) = idx {
            self.get_mut(i)
        } else {
            self.push(get_val());
            self.last_mut()
        }.unwrap()
    }
}
