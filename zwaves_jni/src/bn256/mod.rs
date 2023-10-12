use std::io;

use pairing_ce::bn256::{Bn256, Fr};
use serialization::read_fr_vec;
use verifier::{verify_proof, Proof, TruncatedVerifyingKey};

pub mod serialization;
pub mod verifier;

pub fn groth16_verify(vk: &[u8], proof: &[u8], inputs: &[u8]) -> io::Result<u8> {
    let buff_vk_len = vk.len();
    let buff_proof_len = proof.len();
    let buff_inputs_len = inputs.len();

    if (buff_vk_len % 32 != 0) || (buff_inputs_len % 32 != 0) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "wrong buffer length"));
    }

    let inputs_len = buff_inputs_len / 32;

    if ((buff_vk_len / 32) != (inputs_len + 8)) || (buff_proof_len != 128) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "wrong buffer length"));
    }

    let vk = TruncatedVerifyingKey::<Bn256>::read(vk)?;
    let proof = Proof::<Bn256>::read(proof)?;
    let inputs = read_fr_vec::<Fr>(inputs)?;

    if (inputs.len() != inputs_len) || (vk.ic.len() != (inputs_len + 1)) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "wrong buffer parsing"));
    }

    Ok(verify_proof(&vk, &proof, inputs.as_slice())
        .map(|r| r as u8)
        .unwrap_or(0))
}

#[cfg(test)]
mod local_tests {
    use base64::decode;

    use super::*;
    use test_case::test_case;

    #[test_case(
        "LDCJzjgi5HtcHEXHfU8TZz+ZUHD2ZwsQ7JIEvzdMPYKYs9SoGkKUmg1yya4TE0Ms7x+KOJ4Ze/CPfKp2s5jbniFNM71N/YlHVbNkytLtQi1DzReSh9SNBsvskdY5mavQJe+67PuPVEYnx+lJ97qIG8243njZbGWPqUJ2Vqj49NAunhqX+eIkK3zAB3IPWls3gruzX2t9wrmyE9cVVvf1kgWx63PsQV37qdH0KcFRpCH89k4TPS6fLmqdFxX3YGHCGFTpr6tLogvjbUFJPT98kJ/xck0C0B/s8PTVKdao4VQHT4DBIO8+GB3CQVh6VV4EcMLtDWWNxF4yloAlKcFT0Q4AzJSimpFqd/SwSz9Pb7uk5srte3nwphVamC+fHlJt",
        "GQPBoHuCPcIosF+WZKE5jZV13Ib4EdjLnABncpSHcMKBZl0LhllnPxcuzExIQwhxcfXvFFAjlnDGpKauQ9OQsjBKUBsdBZnGiV2Sg4TSdyHuLo2AbRRqJN0IV3iH3On8I4ngnL30ZAxVyGQH2EK58aUZGxMbbXGR9pQdh99QaiE=",
        "IfZhAypdtgvecKDWzVyRuvXatmFf2ZYcMWVkCJ0/MQo=";
    )]
    #[test_case(
        "oNme33MLprvAodIU3H8rA1WVUVN6IwJtouPFt3rD76EhTyetvNmF9cCLETzYB4K9YC4EIAnZywPddo8kG70hDAeEOBf1FwaXr53SXD0A2pGbHJPRuTTj21tXNXAu7D6MkGKUMCACqi7buNhBbz0X7SKNBgh2Lwxo9CFcv4VBCzkljSjsy0dXI1nUz8oAN99WPRgEqsGtH6wFSllr/AMgKxUVjbIGGpcKvAgvuOfP6HYRsVR8XP7Ecnh/A/aARw4jCycuzPPhJlgjUxs+xCwF/AizkOvYoKFAdFlLKACJIFsIOU8NmXM08eizRXg96hvpfbCVjlWYE1hI90EnJLKTBg==",
        "G3CEMZl39+IlulSqUjmLUP4tB8pnGGteKKU8AlMzkMMcThMVl9rOa5G3DDcm4iF3BFxS3ubW5JADnVvPhX9wNQXMMjh+BKVLUIaC8gwtwciCscaCMw6cIA5ltWuoWX9jB/ig6Yqg4Hc6u2/9XzKfCWG42Si+BkTh8X0DAQ2fAzY=",
        "";
    )]
    #[test_case(
        "nV33RK4rTODU42ZKyFxTFl9d86FrP+h6acIdT4m/rfAZBBfPWLxcjYyMUBHlXgM/jTBDOH7dTGL1zqbRLr1eGwR9zemG9LJnqPl/eiJ0LZLZKz3/iDde8p1zj5DRvar2Fa6rv0WJRJR32+22iaZHrD/64/SyFb2j5f12ipT5S2Eq+SnYSSr8HhStVu3s4VFK57nhi2aRFUgXWkGaqhJJ6ie6zlaVf52s79qdlBUOuTTVsATXa58FVXVSHJb5wanwK578EWV/BulP1TCq5y0q7k6YCZV15Nu9FHpzIUow9Ged8l8LwPmHxki+/S2MnA0v2mFgdC1ZXE+BesWOx3tXThrq7st5+lUMmaY5S76l0yuzzHoeSZEZAoS6heG8WWUGJW2QBTzq3GVaubssoR/HtIT1dGPswNTF8HY78BPYb8M=",
        "pE0Y4zE1A5UvC8ATBJPMOAFm3dDQABrhu5VxxGj5GOom+pFpQsVZe6mMLT8ZwyWXQmJ+od+cYtUOH2Fxiem1yCdMkGi64f5k9qWwYDRrtIxXHhj9f43pHKylJV0Z1jCJgpebExv+hPmwNYh3cWxHxywYMEXwSutAjyqi8Swl1O0=",
        "IfZhAypdtgvecKDWzVyRuvXatmFf2ZYcMWVkCJ0/MQou2EkLZ569itz7cL7GQnzipNe1JRCQ/QK8UXr8IG8k0g==";
    )]
    #[test_case(
        "q1U6rGRU+/F+e3xx6oCBeokQsIVIQDESLC/l+PK8WX0Rw2NglYMRP6In971j7/puuDsJwZm2AK7fTcmKQd5v/g6InaZLdKGQK1C+52BbMyoGsueMfmML9pJmJvivE2N7m9WyiixGvDawwhz7JYst5Jr3ChczYgLAS7b2WQscCRcm8ZE9FKTNdfu4WAYEDEl6IONCFnNiYw6wR8Kc2J7Z9BkHcOzQj2X4PuxZGdPeWF+7vB1dXQZZlCBScImWeVPNKaYF7H3Ot0wOYzigQXYkSZD5v9vBWXN/f1YajxR1kjMrSZ90fx4WapypjaLREbaNgOcAN5niSzTmwymK3e3Idgpt+Pdq34YPOZ5lDx5+3gMWYl1QYeWi6miDIasts0owjZVOTUXf292iZDsjSWaYurcLNEH3Rf8lTCKSMyosjkAV2Fkselh0/Vy4jkPj3hTFeIpY3inMmI+N6Nvwxv50ZpaUIQmU5rlia4pS8MSMxgO+khyyPKb1OUHbFTgDHf6p",
        "mtMjjG0IVNq3t7ICtij1nLFH1UjFu6FaNZmdXam0gdCY/efE2wVHSctp1vqgVcfgiSpl/WCCcaQ2CQGbirLE/wVj2w0eiVEUy6gs9aK01nS0bx4ErymppOugPDPXGCV6FtiAM6Cq+fMbOKhhhDPutn6dIntO3gSqtsWL0KreCPY=",
        "IfZhAypdtgvecKDWzVyRuvXatmFf2ZYcMWVkCJ0/MQou2EkLZ569itz7cL7GQnzipNe1JRCQ/QK8UXr8IG8k0hW3GAoAXun/Pwk0Jq9fst26FET2RehSLbxUdvZQLjEzCJmfahCreklII85wEMuwYctsOv/3JWgvrI8hmn8sWjw=";
    )]
    #[test_case(
        "kikeX/IlYwL5e1nkJ3FbD4/IantLORJJtmgMPywFCoCdYF304ka26knjzRodk7mujA0HqXxknBkzZSqQuuqcSSZkVOudYO1dwOw73U9SlL/nF4UWP4YOkVfKntqi825LkCrBcl3rw7zhMHorldspOwWNVybCLGt86Zbd92hze3wcSIk2GqMxtoBQiurYqlt1SARwIn06tRExJ0YULl/7/4qrYi+Tsjy0xQwltrHJQy/eeVNNq9x/GrVJemN2r+SUK6lF6kWLJzTH5jUUu7HvpUCtRlGJ3JRZIAJ7qChT3v+fD5LNjz86Ei1ItV4Wgqk/iXAAXeORUM3T3RD2NepVgS3U35HXhJ1ZtzJZoFUQyQjlGYp6+U6q8+rXYSQkZjEHmQh/Atr0lb1QRIG+PK+mLj1Nxwb/aibt7z7WtRTfj3mudYCEjXA/ceDVtz8FKkeTo9dcVYGsf/VJaxnteVa7B4UMRQjX0gdNKC+AEjKxcRk373IqLBCCtukQYBG8o2TKFYfJcJuI1geuGtNij1jwgmLxl7hH3Y0JqMZPoS9vKwudBL5Nnt38g/rfNTyoe7UIJV246oAOkuuskfxNUHeEnILjkHYhjfIuuPMGUG4FK2LHkscqib6eHo3wSy31I65urmsiHROrMEtfUdYcGDJxV+IyrTUs2m5KQgmlXo8jvUo=",
        "HUaOoIyn6KUkVXzttFMcRobGBZUtpRjAQMId9n3ABZKPUk8Rv0EPKmzp/1Ut0LNJ5cNI48VwD6/kVbhNgoBbdQijsqDktFjjeJtzj6KF2TuHOlcHL6s7dc38cvNVD0O1ISiJlLdrc5QKcXePAGJK/YaD/CUQfKnijgCGDREUDXo=",
        "IfZhAypdtgvecKDWzVyRuvXatmFf2ZYcMWVkCJ0/MQou2EkLZ569itz7cL7GQnzipNe1JRCQ/QK8UXr8IG8k0hW3GAoAXun/Pwk0Jq9fst26FET2RehSLbxUdvZQLjEzCJmfahCreklII85wEMuwYctsOv/3JWgvrI8hmn8sWjwELKgjqMSLQgJ7u5ZHe9PDhBgF/3dliXhY1jUsXFvkig6pfEr0bFuXhXcg2R+vuPErhG0w08SPNOi2SjvPngYpJ8nsOT98G6EDlyNaHtJuRC/xOA+6ftL/k2+hzFsd+1Ui5/1NGTfDxLDndEE1NQ+opvk79ZeaY+qPP7pEc0uQMw==";
    )]
    #[test_case(
        "qladoBQdTIMTqRD5nLplvCqxlHwZrFv7scw72CqqjkMsK1J9mo3aYYCS8MXIl224CTjyJF/IQ2nFONXeSUdoFAFN1RfVylmeW3Qbeqj8ePv9JA+LjpgE68Zr9u85DqI4hK+0BABhe1S+m79CtKaSOAt7pJNDmiNqEKsGYDBhYBIBLAdgsmLkOfA197v06p/UaXCOXvNQMjprjuvt3SCrkoV8jZU/cSrB+cPPE8s4OgVl0eXr08YRmmDym/veV4eTI1WV59Qxb3uZCOtJFPwwd6gTiXvnGhhWrgJPwjAIJhmFDEUI19IHTSgvgBIysXEZN+9yKiwQgrbpEGARvKNkyhWHyXCbiNYHrhrTYo9Y8IJi8Ze4R92NCajGT6EvbysLnQS+TZ7d/IP63zU8qHu1CCVduOqADpLrrJH8TVB3hJyC45B2IY3yLrjzBlBuBStix5LHKom+nh6N8Est9SOubq5rIh0TqzBLX1HWHBgycVfiMq01LNpuSkIJpV6PI71KmXEqw09G6gPAM1465XNSWZV0gLUTctlavUWfG7jILPafEBGrM69wVNmnBm0lSOq9fBTatb8Ivm4+SDNHALraRo1guaelsx+MuKox7hj5WkuIjo7PSprYHsM6Wc3/10VpJQwX6/Dp5J0MZzYscKLlGX5DXXbaQLcIT6I+cjioLcIwK20hLc56+CaCSZRyKMB9IWUmavploHQrjBW+vyyOPQNIbqUTWjTVHJ9QCCdVxUWP+0yHwCjZUymqnVoG6HrPkYvh0nuIsz552K6SWFMuhddTW+JN/uUIpniAKCI4WwafIl/0mH/DRktCA5uQdpevX62mWKfyYGL1if6TV20CgSMvo6fiK+yC5GCzMKtsHxMFWW5fYkjQ2b/C8RWjCySpDQPFVqJwr5uMYxdqtsSs7ysGZfpoRZS1SDbVgFVL1E6d/ECJMiqIOM0OH0uBRzF7B3q2BT5GChq/naHPEucCcBU8HgairQQ3uV+V+UyWbYmrwjGQZSg0pSQ3Jff41MGe",
        "CfEpVT6b8+4NAeDs3QwiSN7zqfxzAkQdIu8eBXzoAQIS+AgJcYppUx7COvtbWa7TDtaER1ydtoYWBcBtRMvrHQJ64u4XmLooTwikzECPz+VRcYknrGEoyGeZanNFWEwgplf9bX3JvW1RshlAfN7iJESdqBCmUNsrObHNxhHFJRo=",
        "IfZhAypdtgvecKDWzVyRuvXatmFf2ZYcMWVkCJ0/MQou2EkLZ569itz7cL7GQnzipNe1JRCQ/QK8UXr8IG8k0hW3GAoAXun/Pwk0Jq9fst26FET2RehSLbxUdvZQLjEzCJmfahCreklII85wEMuwYctsOv/3JWgvrI8hmn8sWjwELKgjqMSLQgJ7u5ZHe9PDhBgF/3dliXhY1jUsXFvkig6pfEr0bFuXhXcg2R+vuPErhG0w08SPNOi2SjvPngYpJ8nsOT98G6EDlyNaHtJuRC/xOA+6ftL/k2+hzFsd+1Ui5/1NGTfDxLDndEE1NQ+opvk79ZeaY+qPP7pEc0uQMxnEIHHpcYsRt9dal9bSQpE5hWKu1nOBzIVmXb/Ef51YDg+nW5w9a2tEAY2zQCZ/z3sFs7FwAZ5TXhDfhYR5sQ8tZaF3FWh+Yzf5hgMmXWrApp/arwPszNhKCoxScnhPSgfcxYSdauqvp5+vcacJFY1OkWG6tQ6iuh5CZSdX645oA7oNr9d5kXYSewhTflcV9pufeaH21BtEipHpO3sNRkUngnHC+uj1D8ReSgcCofnv8s0mVme9Ml64r6CbeaHK+x5Mc9bolN96XJZ137xkPDpev+RVrVK6ZIFrH2hFl8/vGoBwWDlmjmVzUt4YQdsCavsf7c0vBa7d33EcvyvQMDY=";
    )]
    fn groth16_verify_ok_test(vk_b64: &str, proof_b64: &str, inputs_b64: &str) {
        let vk = decode(&vk_b64).unwrap();
        let proof = decode(&proof_b64).unwrap();
        let inputs = decode(&inputs_b64).unwrap();

        let res = groth16_verify(&vk, &proof, &inputs).unwrap_or(0) != 0;
        assert!(res, "groth16_verify should return true");
    }

    #[test_case(
        vec![1; 256],
        "CfEpVT6b8+4NAeDs3QwiSN7zqfxzAkQdIu8eBXzoAQIS+AgJcYppUx7COvtbWa7TDtaER1ydtoYWBcBtRMvrHQJ64u4XmLooTwikzECPz+VRcYknrGEoyGeZanNFWEwgplf9bX3JvW1RshlAfN7iJESdqBCmUNsrObHNxhHFJRo=",
        "";
        "256 byte vk, empty inputs"
    )]
    #[test_case(
        [1; 256 + 32].to_vec(),
        "CfEpVT6b8+4NAeDs3QwiSN7zqfxzAkQdIu8eBXzoAQIS+AgJcYppUx7COvtbWa7TDtaER1ydtoYWBcBtRMvrHQJ64u4XmLooTwikzECPz+VRcYknrGEoyGeZanNFWEwgplf9bX3JvW1RshlAfN7iJESdqBCmUNsrObHNxhHFJRo=",
        "c9BSUPtO0xjPxWVNkEMfXe7O4UZKpaH/nLIyQJj7iA4=";
        "288 byte vk"
    )]
    #[test_case(
        [1; 256 + 32 * 15].to_vec(),
        "CfEpVT6b8+4NAeDs3QwiSN7zqfxzAkQdIu8eBXzoAQIS+AgJcYppUx7COvtbWa7TDtaER1ydtoYWBcBtRMvrHQJ64u4XmLooTwikzECPz+VRcYknrGEoyGeZanNFWEwgplf9bX3JvW1RshlAfN7iJESdqBCmUNsrObHNxhHFJRo=",
        "I8C5RcBDPi2n4omt9oOV2rZk9T9xlSV8PQvLeVHjGb00fCVz7AHOIjLJ03ZCTLQwEKkAk9tQWJ6gFTBnG2+0DDHlXcVkwpMafcpS2diKFe0T4fRb0t9mxNzOFiRVcJoeMU1zb/rE4dIMm9rbEPSDnVSOd8tHNnJDkT+/NcNsQ2w0UEVJJRAEnC7G0Y3522RlDLxpTZ6w0U/9V0pLNkFgDCkFBKvpaEfPDJjoEVyCUWDC1ts9LIR43xh3ZZBdcO/HATHoLzxM3Ef11qF+riV7WDPEJfK11u8WGazzCAFhsx0aKkkbnKl7LnypBzwRvrG2JxdLI/oXL0eoIw9woVjqrg6elHudnHDXezDVXjRWMPaU+L3tOW9aqN+OdP4AhtpgT2CoRCjrOIU3MCFqsrCK9bh33PW1gtNeHC78mIetQM5LWZHtw4KNwafTrQ+GCKPelJhiC2x7ygBtat5rtBsJAVF5wjssLPZx/7fqNqifXB7WyMV7J1M8LBQVXj5kLoS9bpmNHlERRSadC0DEUbY9xhIG2xo7R88R0sq04a299MFv8XJNd+IdueYiMiGF5broHD4UUhPxRBlBO3lOfDTPnRSUGS3Sr6GxwCjKO3MObz/6RNxCk9SnQ4NccD17hS/m";
        "736 byte vk"
    )]
    #[test_case(
        [1; 256 + 32 * 16].to_vec(),
        "CfEpVT6b8+4NAeDs3QwiSN7zqfxzAkQdIu8eBXzoAQIS+AgJcYppUx7COvtbWa7TDtaER1ydtoYWBcBtRMvrHQJ64u4XmLooTwikzECPz+VRcYknrGEoyGeZanNFWEwgplf9bX3JvW1RshlAfN7iJESdqBCmUNsrObHNxhHFJRo=",
        "I8C5RcBDPi2n4omt9oOV2rZk9T9xlSV8PQvLeVHjGb00fCVz7AHOIjLJ03ZCTLQwEKkAk9tQWJ6gFTBnG2+0DDHlXcVkwpMafcpS2diKFe0T4fRb0t9mxNzOFiRVcJoeMU1zb/rE4dIMm9rbEPSDnVSOd8tHNnJDkT+/NcNsQ2w0UEVJJRAEnC7G0Y3522RlDLxpTZ6w0U/9V0pLNkFgDCkFBKvpaEfPDJjoEVyCUWDC1ts9LIR43xh3ZZBdcO/HATHoLzxM3Ef11qF+riV7WDPEJfK11u8WGazzCAFhsx0aKkkbnKl7LnypBzwRvrG2JxdLI/oXL0eoIw9woVjqrg6elHudnHDXezDVXjRWMPaU+L3tOW9aqN+OdP4AhtpgT2CoRCjrOIU3MCFqsrCK9bh33PW1gtNeHC78mIetQM5LWZHtw4KNwafTrQ+GCKPelJhiC2x7ygBtat5rtBsJAVF5wjssLPZx/7fqNqifXB7WyMV7J1M8LBQVXj5kLoS9bpmNHlERRSadC0DEUbY9xhIG2xo7R88R0sq04a299MFv8XJNd+IdueYiMiGF5broHD4UUhPxRBlBO3lOfDTPnRSUGS3Sr6GxwCjKO3MObz/6RNxCk9SnQ4NccD17hS/mEFt8d4ERZOfmuvD3A0RCPCnx3Fr6rHdm6j+cfn/NM6o=";
        "768 byte vk"
    )]
    fn groth16_verify_fail_test(vk: Vec<u8>, proof_b64: &str, inputs_b64: &str) {
        let proof = base64::decode(proof_b64).expect("Invalid base64 in proof");
        let inputs = base64::decode(inputs_b64).expect("Invalid base64 in inputs");

        let res = groth16_verify(&vk, &proof, &inputs).unwrap_or(0) != 0;
        assert!(!res, "groth16_verify should return false");
    }
}
