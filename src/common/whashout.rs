use std::{fmt::Display, str::FromStr};

use anyhow::ensure;
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, Sample},
    },
    hash::hash_types::{HashOut, RichField},
    plonk::config::GenericHashOut,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::serde_as;


#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WHashOut<F: Field>(pub HashOut<F>);
pub type GoldilocksHashOut = WHashOut<GoldilocksField>;

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SerializableHashOut(#[serde_as(as = "serde_with::hex::Hex")] pub Vec<u8>);

impl<F: RichField> Serialize for WHashOut<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = self.0.to_bytes(); // little endian
        bytes.reverse(); // big endian
        let raw = SerializableHashOut(bytes);

        raw.serialize(serializer)
    }
}

impl<'de, F: RichField> Deserialize<'de> for WHashOut<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = SerializableHashOut::deserialize(deserializer)?;
        let mut bytes = raw.0;
        if bytes.len() > 32 {
            return Err(serde::de::Error::custom("too long hexadecimal sequence"));
        }
        bytes.reverse(); // little endian
        bytes.resize(32, 0);

        Ok(WHashOut(HashOut::from_bytes(&bytes)))
    }
}

impl<F: Field> Default for WHashOut<F> {
    fn default() -> Self {
        WHashOut(HashOut::ZERO)
    }
}

impl<F: Field> From<WHashOut<F>> for HashOut<F> {
    fn from(value: WHashOut<F>) -> Self {
        value.0
    }
}
impl<F: Field> From<HashOut<F>> for WHashOut<F> {
    fn from(value: HashOut<F>) -> Self {
        WHashOut(value)
    }
}

impl<F: RichField> TryFrom<&[F]> for WHashOut<F> {
    type Error = anyhow::Error;

    fn try_from(elements: &[F]) -> Result<Self, Self::Error> {
        ensure!(elements.len() == 4);
        Ok(Self(HashOut {
            elements: elements.try_into().unwrap(),
        }))
    }
}


impl<F: RichField> TryFrom<&[u64; 4]> for WHashOut<F> {
    type Error = anyhow::Error;

    fn try_from(elements: &[u64; 4]) -> Result<Self, Self::Error> {
        Ok(Self(HashOut {
            elements: [
                F::from_noncanonical_u64(elements[0]),
                F::from_noncanonical_u64(elements[1]),
                F::from_noncanonical_u64(elements[2]),
                F::from_noncanonical_u64(elements[3]),
            ]
        }))
    }
}
impl<F: RichField> Display for WHashOut<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self)
            .map(|v| v.replace('\"', ""))
            .unwrap();

        write!(f, "{}", s)
    }
}

impl<F: RichField> FromStr for WHashOut<F> {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let json = "\"".to_string() + s + "\"";

        serde_json::from_str(&json)
    }
}

impl<F: RichField> GenericHashOut<F> for WHashOut<F> {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        WHashOut(HashOut::from_bytes(bytes))
    }

    fn to_vec(&self) -> Vec<F> {
        self.0.to_vec()
    }
}
impl<F: RichField> WHashOut<F> {
    pub const ZERO: Self = Self(HashOut::<F>::ZERO);

    pub fn from_string_or_panic(s: &str) -> Self {
        let json = "\"".to_string() + s + "\"";

        serde_json::from_str(&json).unwrap()
    }
    pub fn rand() -> Self {
        Self(HashOut::rand())
    }
    pub fn from_values(a: u64, b: u64, c: u64, d: u64) -> Self {
        Self(HashOut {
            elements: [
                F::from_noncanonical_u64(a),
                F::from_noncanonical_u64(b),
                F::from_noncanonical_u64(c),
                F::from_noncanonical_u64(d),
            ],
        })
    }
}