use rand::seq::SliceRandom;
use rand::{Rng, thread_rng};

pub const NOUNS: &[&str] = &[
    "boop", "doodle", "puddle", "quack", "muffin", "goober", "snoot", "giggle", "bop", "whisker",
    "nom", "plop", "dork", "floop", "gizmo", "splat", "quantum", "neutrino", "quasar", "photon",
    "singularity", "wormhole", "tachyon", "electron", "nanobot", "algorithm", "bitwise", "compiler",
    "debug", "lambda", "integer", "boolean", "syntax", "cosmos", "kepler", "galaxy", "orion", "asteroid",
    "einstein", "hawking", "sagan", "curie", "turing", "lovelace", "noether", "franklin", "hopper", "hypatia",
    "hypotenuse", "derivative", "integral", "matrix", "vector", "bytecode", "binary", "unicode", "ascii",
    "mecha", "kaiju", "alchemist", "neko", "sakura", "mochi", "pulsar", "nebula", "supernova", "event",
    "horizon", "plasma", "hadron", "lepton", "muon", "gluon", "qubit", "circuit", "tesseract", "fractal",
    "chaos", "entropy", "vortex", "darkmatter", "ion", "molecule", "enzyme", "proton", "neutron", "xenon",
    "zenith", "algorithm", "byte", "cypher", "hash", "vector", "cache", "module", "qubit", "relativity",
    "dimension", "spectrometer", "fusion", "graviton", "neutrino", "photonics", "transistor", "waveform"
];

pub const DESCRIPTORS: &[&str] = &[
    "fluffy", "wobble", "sizzle", "wiggle", "fizzy", "bouncy", "zippy", "jolly", "snuggle", "bubbly",
    "entangle", "recursive", "hyperbolic", "kawaii", "sparkly", "whimsical", "quirky", "luminous", "radiant",
    "electric", "glitchy", "holographic", "cosmic", "stellar", "nebular", "fractal", "chaotic", "magnetic",
    "turbulent", "vibrant", "eccentric", "playful", "curious", "arcane", "dynamic", "harmonic", "theoretical",
    "cryptic", "geometric", "spectral", "synthetic", "exponential", "futuristic", "transcendent", "celestial",
    "quantized", "gravitational", "algorithmic", "recursive", "parallel", "complex", "prismatic", "galactic",
    "dimensional", "nonlinear", "abstract", "syntactical", "logical", "computational", "probabilistic",
    "symmetrical", "asymptotic", "topological", "analytic", "kinetic", "theorematic", "numeric", "ludic",
    "chaotic", "harmonic", "cybernetic", "astronomical", "holographic", "metaphysical", "symmetric", "relativistic"
];

pub fn generate_random_name() -> String {
    let mut rng = thread_rng();
    let first = DESCRIPTORS.choose(&mut rng).unwrap();
    let second = NOUNS.choose(&mut rng).unwrap();
    let mut number: u16 = rng.gen_range(0..10000); // 4-digit number

    // if number contains any two or more 8's next to each other
    // change each 8 to a random digit from 0 7 or 9
    if number.to_string().contains("88") {
        let mut digits = number.to_string().chars().collect::<Vec<char>>();
        for i in 0..digits.len() - 1 {
            if digits[i] == '8' && digits[i + 1] == '8' {
                let mut new_numb = rng.gen_range(0..9);
                if new_numb >= 8 {
                    new_numb += 1;
                }

                // use + 0 or + 1 to decide at random which digit to replace
                let index_padding = rng.gen_range(0..2);
                digits[i + index_padding] = char::from_digit(new_numb, 10).unwrap();

                // randomly decide to update both or just one
                let update_both = rng.gen_range(0..2);
                if update_both == 1 {
                    new_numb = rng.gen_range(0..9);
                    if new_numb >= 8 {
                        new_numb += 1;
                    }
                    digits[i + 1 - index_padding] = char::from_digit(new_numb, 10).unwrap();
                }
            }
        }
        number = digits.iter().collect::<String>().parse().unwrap();
    }

    format!("{}-{}-{:04}", first, second, number).to_string()
}
