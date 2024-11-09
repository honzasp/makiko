use bytes::Bytes;
use ecdsa::elliptic_curve;
use ecdsa::elliptic_curve::generic_array;
use ecdsa::elliptic_curve::generic_array::typenum;
use ecdsa::signature;
use ecdsa::signature::digest;
use ecdsa::signature::digest::crypto_common;
use std::fmt;
use num_bigint_dig::BigUint;
use crate::codec::{PacketDecode, PacketEncode};
use crate::error::{Result, Error};
use super::{PubkeyAlgo, Pubkey, Privkey, SignatureVerified};

/// "ecdsa-sha2-nistp256" public key algorithm from RFC 5656.
///
/// This algorithm is compatible with [`EcdsaPubkey<p256::NistP256>`] and
/// [`EcdsaPrivkey<p384::NistP384>`].
pub static ECDSA_SHA2_NISTP256: PubkeyAlgo = PubkeyAlgo {
    name: "ecdsa-sha2-nistp256",
    verify: verify::<p256::NistP256>,
    sign: sign::<p256::NistP256>,
};

/// "ecdsa-sha2-nistp384" public key algorithm from RFC 5656.
///
/// This algorithm is compatible with [`EcdsaPubkey<p384::NistP384>`] and
/// [`EcdsaPrivkey<p384::NistP384>`].
pub static ECDSA_SHA2_NISTP384: PubkeyAlgo = PubkeyAlgo {
    name: "ecdsa-sha2-nistp384",
    verify: verify::<p384::NistP384>,
    sign: sign::<p384::NistP384>,
};

/// ECDSA public key using curve `C`.
///
/// - `EcdsaPubkey<p256::NistP256>` is compatible with [`ECDSA_SHA2_NISTP256`].
/// - `EcdsaPubkey<p384::NistP384>` is compatible with [`ECDSA_SHA2_NISTP384`].
///
/// You can convert it to and from [`ecdsa::VerifyingKey<C>`] and [`elliptic_curve::PublicKey<C>`]
/// using `from()`/`into()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaPubkey<C: Curve>
    where <C as elliptic_curve::CurveArithmetic>::Scalar: ecdsa::hazmat::SignPrimitive<C>,
          ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
{
    verifying: ecdsa::VerifyingKey<C>,
}

/// ECDSA private key using curve `C`.
///
/// - `EcdsaPrivkey<p256::NistP256>` is compatible with [`ECDSA_SHA2_NISTP256`].
/// - `EcdsaPrivkey<p384::NistP384>` is compatible with [`ECDSA_SHA2_NISTP384`].
///
/// You can convert it to and from [`ecdsa::SigningKey<C>`] and [`elliptic_curve::SecretKey<C>`]
/// using `from()`/`into()`.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "debug-less-secure", derive(Debug))]
pub struct EcdsaPrivkey<C: Curve>
    where <C as elliptic_curve::CurveArithmetic>::Scalar: ecdsa::hazmat::SignPrimitive<C>,
          ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
{
    signing: ecdsa::SigningKey<C>,
}

impl EcdsaPrivkey<p256::NistP256> {
    /// Get the public key associated with this private key.
    pub fn pubkey(&self) -> EcdsaPubkey<p256::NistP256> {
        EcdsaPubkey { verifying: *self.signing.verifying_key() }
    }
}

impl EcdsaPrivkey<p384::NistP384> {
    /// Get the public key associated with this private key.
    pub fn pubkey(&self) -> EcdsaPubkey<p384::NistP384> {
        EcdsaPubkey { verifying: *self.signing.verifying_key() }
    }
}


fn verify<C: Curve>(pubkey: &Pubkey, message: &[u8], signature: Bytes) -> Result<SignatureVerified> 
    where <C as elliptic_curve::CurveArithmetic>::Scalar: ecdsa::hazmat::SignPrimitive<C>,
          ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
          elliptic_curve::AffinePoint<C>: ecdsa::hazmat::VerifyPrimitive<C>,
          C::Digest: digest::FixedOutput<OutputSize = elliptic_curve::FieldBytesSize<C>>,
{
    let verifying = C::extract_verifying(pubkey)?;

    let mut signature = PacketDecode::new(signature);
    if signature.get_string()? != C::ALGO_NAME {
        return Err(Error::Decode("unexpected signature format"))
    }

    let to_field_bytes = |scalar: BigUint| -> Result<elliptic_curve::FieldBytes<C>> {
        use typenum::Unsigned as _;
        let scalar = scalar.to_bytes_be();
        if scalar.len() <= elliptic_curve::FieldBytesSize::<C>::to_usize() {
            let mut scalar_bytes = elliptic_curve::FieldBytes::<C>::default();
            let copy_idx = scalar_bytes.len() - scalar.len();
            scalar_bytes[copy_idx..].copy_from_slice(&scalar);
            Ok(scalar_bytes)
        } else {
            Err(Error::Signature)
        }
    };

    let mut signature_blob = PacketDecode::new(signature.get_bytes()?);
    let r = to_field_bytes(signature_blob.get_biguint()?)?;
    let s = to_field_bytes(signature_blob.get_biguint()?)?;

    use digest::Digest as _;
    let digest = C::Digest::new_with_prefix(message);
    let ecdsa_signature = ecdsa::Signature::from_scalars(r, s)
        .map_err(|_| Error::Signature)?;

    use signature::DigestVerifier as _;
    match verifying.verify_digest(digest, &ecdsa_signature) {
        Ok(_) => Ok(SignatureVerified::assertion()),
        Err(_) => Err(Error::Signature),
    }
}

fn sign<C: Curve>(privkey: &Privkey, message: &[u8]) -> Result<Bytes>
    where <C as elliptic_curve::CurveArithmetic>::Scalar: ecdsa::hazmat::SignPrimitive<C>,
          ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
          C::Digest: crypto_common::BlockSizeUser,
          C::Digest: digest::FixedOutput<OutputSize = elliptic_curve::FieldBytesSize<C>>,
          C::Digest: digest::FixedOutputReset,
{
    let signing = C::extract_signing(privkey)?;

    let from_field_bytes = |scalar: elliptic_curve::FieldBytes<C>| -> BigUint {
        BigUint::from_bytes_be(&scalar)
    };

    use digest::Digest as _;
    let digest = C::Digest::new_with_prefix(message);

    use signature::DigestSigner as _;
    let ecdsa_signature: ecdsa::Signature<C> = signing.sign_digest(digest);
    let (r, s) = ecdsa_signature.split_bytes();
    let r = from_field_bytes(r);
    let s = from_field_bytes(s);

    let mut signature_blob = PacketEncode::new();
    signature_blob.put_biguint(&r);
    signature_blob.put_biguint(&s);

    let mut signature = PacketEncode::new();
    signature.put_str(C::ALGO_NAME);
    signature.put_bytes(&signature_blob.finish());
    Ok(signature.finish())
}

pub(super) fn decode_pubkey<C: Curve>(blob: &mut PacketDecode) -> Result<EcdsaPubkey<C>>
    where <C as elliptic_curve::CurveArithmetic>::Scalar: ecdsa::hazmat::SignPrimitive<C>,
          ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
          elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
          elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::ToEncodedPoint<C>,
          elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>,
{
    if blob.get_string()? != C::CURVE_NAME {
        return Err(Error::Decode("bad curve name in ecdsa public key"))
    }

    let encoded_point = blob.get_bytes()?;
    let encoded_point = elliptic_curve::sec1::EncodedPoint::<C>::from_bytes(&encoded_point)
        .map_err(|_| Error::Decode("ecdsa public key is invalid (bad bytes)"))?;
    
    use elliptic_curve::sec1::FromEncodedPoint as _;
    let public_key: Option<elliptic_curve::PublicKey<C>> =
        elliptic_curve::PublicKey::from_encoded_point(&encoded_point).into();
    let public_key = public_key.ok_or(Error::Decode("ecdsa public key is invalid (bad point)"))?;

    Ok(EcdsaPubkey { verifying: public_key.into() })
}

pub(super) fn encode_pubkey<C: Curve>(blob: &mut PacketEncode, pubkey: &EcdsaPubkey<C>)
    where <C as elliptic_curve::CurveArithmetic>::Scalar: ecdsa::hazmat::SignPrimitive<C>,
          ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
          elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
          elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::ToEncodedPoint<C>,
          elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>,
{
    use elliptic_curve::sec1::ToEncodedPoint as _;
    let public_key: elliptic_curve::PublicKey<C> = pubkey.verifying.into();
    let encoded_point = public_key.to_encoded_point(false);

    blob.put_str(C::ALGO_NAME);
    blob.put_str(C::CURVE_NAME);
    blob.put_bytes(encoded_point.as_bytes());
}

pub(super) fn decode_privkey<C: Curve>(blob: &mut PacketDecode) -> Result<EcdsaPrivkey<C>>
    where <C as elliptic_curve::CurveArithmetic>::Scalar: ecdsa::hazmat::SignPrimitive<C>,
          ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
          elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
          elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::ToEncodedPoint<C>,
          elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>,
{
    if blob.get_string()? != C::CURVE_NAME {
        return Err(Error::Decode("bad curve name in ecdsa private key"));
    }

    let encoded_point = blob.get_bytes()?;
    let encoded_point = elliptic_curve::sec1::EncodedPoint::<C>::from_bytes(&encoded_point)
        .map_err(|_| Error::Decode("ecdsa private key is invalid (bad bytes of public point)"))?;

    use elliptic_curve::sec1::FromEncodedPoint as _;
    let public_key: Option<elliptic_curve::PublicKey<C>> =
        elliptic_curve::PublicKey::from_encoded_point(&encoded_point).into();
    let public_key = public_key.ok_or(Error::Decode("ecdsa private key is invalid (bad public point)"))?;

    use typenum::Unsigned as _;
    let secret_scalar = blob.get_scalar(elliptic_curve::FieldBytesSize::<C>::to_usize())?;
    let secret_scalar = generic_array::GenericArray::from_slice(&secret_scalar);
    let secret_key = elliptic_curve::SecretKey::<C>::from_bytes(secret_scalar)
        .map_err(|_| Error::Decode("ecdsa private key is invalid (bad bytes of private scalar)"))?;

    if secret_key.public_key() != public_key {
        return Err(Error::Decode("ecdsa private key is invalid (public key does not match private key)"));
    }

    Ok(EcdsaPrivkey { signing: secret_key.into() })
}



pub trait Curve: ecdsa::PrimeCurve + elliptic_curve::CurveArithmetic + ecdsa::hazmat::DigestPrimitive
    where <Self as elliptic_curve::CurveArithmetic>::Scalar: ecdsa::hazmat::SignPrimitive<Self>,
          ecdsa::SignatureSize<Self>: generic_array::ArrayLength<u8>,
{
    const ALGO_NAME: &'static str;
    const CURVE_NAME: &'static str;

    fn extract_verifying(pubkey: &Pubkey) -> Result<&ecdsa::VerifyingKey<Self>>;
    fn extract_signing(privkey: &Privkey) -> Result<&ecdsa::SigningKey<Self>>;
}

impl Curve for p256::NistP256 {
    const ALGO_NAME: &'static str = "ecdsa-sha2-nistp256";
    const CURVE_NAME: &'static str = "nistp256";

    fn extract_verifying(pubkey: &Pubkey) -> Result<&ecdsa::VerifyingKey<Self>> {
        match pubkey {
            Pubkey::EcdsaP256(pubkey) => Ok(&pubkey.verifying),
            _ => Err(Error::PubkeyFormat),
        }
    }

    fn extract_signing(privkey: &Privkey) -> Result<&ecdsa::SigningKey<Self>> {
        match privkey {
            Privkey::EcdsaP256(privkey) => Ok(&privkey.signing),
            _ => Err(Error::PrivkeyFormat),
        }
    }
}

impl Curve for p384::NistP384 {
    const ALGO_NAME: &'static str = "ecdsa-sha2-nistp384";
    const CURVE_NAME: &'static str = "nistp384";

    fn extract_verifying(pubkey: &Pubkey) -> Result<&ecdsa::VerifyingKey<Self>> {
        match pubkey {
            Pubkey::EcdsaP384(pubkey) => Ok(&pubkey.verifying),
            _ => Err(Error::PubkeyFormat),
        }
    }

    fn extract_signing(privkey: &Privkey) -> Result<&ecdsa::SigningKey<Self>> {
        match privkey {
            Privkey::EcdsaP384(privkey) => Ok(&privkey.signing),
            _ => Err(Error::PrivkeyFormat),
        }
    }
}


impl<C: Curve> From<ecdsa::VerifyingKey<C>> for EcdsaPubkey<C> 
    where <C as elliptic_curve::CurveArithmetic>::Scalar: ecdsa::hazmat::SignPrimitive<C>,
          ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
{
    fn from(verifying: ecdsa::VerifyingKey<C>) -> Self { Self { verifying } }
}

impl<C: Curve> From<elliptic_curve::PublicKey<C>> for EcdsaPubkey<C>
    where <C as elliptic_curve::CurveArithmetic>::Scalar: ecdsa::hazmat::SignPrimitive<C>,
          ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
{
    fn from(public: elliptic_curve::PublicKey<C>) -> Self { Self { verifying: public.into() } }
}

impl<C: Curve> From<EcdsaPubkey<C>> for ecdsa::VerifyingKey<C>
    where <C as elliptic_curve::CurveArithmetic>::Scalar: ecdsa::hazmat::SignPrimitive<C>,
          ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
{
    fn from(pubkey: EcdsaPubkey<C>) -> Self { pubkey.verifying }
}

impl<C: Curve> From<EcdsaPubkey<C>> for elliptic_curve::PublicKey<C>
    where <C as elliptic_curve::CurveArithmetic>::Scalar: ecdsa::hazmat::SignPrimitive<C>,
          ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
{
    fn from(pubkey: EcdsaPubkey<C>) -> Self { pubkey.verifying.into() }
}

impl<C: Curve> From<ecdsa::SigningKey<C>> for EcdsaPrivkey<C>
    where <C as elliptic_curve::CurveArithmetic>::Scalar: ecdsa::hazmat::SignPrimitive<C>,
          ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
{
    fn from(signing: ecdsa::SigningKey<C>) -> Self { Self { signing } }
}

impl<C: Curve> From<elliptic_curve::SecretKey<C>> for EcdsaPrivkey<C>
    where <C as elliptic_curve::CurveArithmetic>::Scalar: ecdsa::hazmat::SignPrimitive<C>,
          ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
{
    fn from(secret: elliptic_curve::SecretKey<C>) -> Self { Self { signing: secret.into() } }
}

impl<C: Curve> From<EcdsaPrivkey<C>> for ecdsa::SigningKey<C>
    where <C as elliptic_curve::CurveArithmetic>::Scalar: ecdsa::hazmat::SignPrimitive<C>,
          ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
{
    fn from(privkey: EcdsaPrivkey<C>) -> Self { privkey.signing }
}

impl fmt::Display for EcdsaPubkey<p256::NistP256> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = Bytes::copy_from_slice(&self.verifying.to_encoded_point(true).to_bytes());
        write!(f, "ecdsa-nistp256 {:x}", bytes)
    }
}

impl fmt::Display for EcdsaPubkey<p384::NistP384> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = Bytes::copy_from_slice(&self.verifying.to_encoded_point(true).to_bytes());
        write!(f, "ecdsa-nistp384 {:x}", bytes)
    }
}

