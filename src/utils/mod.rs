use distance::sift3;

// the Threshold struct which will be used as a range
// to tell how far appart the responses are from the web root
struct Threshold {
    threshold_start: f32,
    threshold_end: f32,
}
// make it global :)
const CHANGE: Threshold = Threshold {
    threshold_start: 500.0,
    threshold_end: 500000.0,
};
// uses the sift3 alogirthm to find the differences between to str inputs.
pub fn get_response_change(a: &str, b: &str) -> (bool, f32) {
    let s = sift3(a, b);
    if s > CHANGE.threshold_start && s < CHANGE.threshold_end {
        return (true, s);
    }
    return (false, 0.0);
}
