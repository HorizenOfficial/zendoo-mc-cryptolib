use algebra::{
    fields::mnt4753::Fr,
    curves::mnt6753::G1Projective,
    biginteger::BigInteger768,
    Field, PrimeField,
};

use crypto_primitives::signature::schnorr::field_impl::FieldBasedSchnorrSignature;

pub struct NaiveThresholdSigParams{
    pub null_sig:   FieldBasedSchnorrSignature<Fr>,
    pub null_pk:    G1Projective,
}

impl NaiveThresholdSigParams {
    pub fn new() -> Self {
        let e = Fr::one();
        let s = e.clone();
        let null_sig = FieldBasedSchnorrSignature::<Fr>{e, s};

        //Not trustable, because computed with a randomly sampled generator
        let x = Fr::from_repr(
            BigInteger768([
                5271036332085560848,
                17135351094704181526,
                6378363630417444613,
                15831336963444071575,
                17315325320978726939,
                15360300524170484090,
                12266069760683936557,
                9951801177676220396,
                5407059963535829214,
                717013909087980498,
                2598949996860420976,
                54430560438109,
            ]));

        let y = Fr::from_repr(
            BigInteger768([
                15929885692800419708,
                12658368288797143572,
                3754492562011345008,
                6927657603082571132,
                12154606688048963531,
                11990938568373544327,
                8201889093209173211,
                2788558746462053181,
                446551938461937000,
                15205596413647351513,
                819369269629061920,
                372148950779690,
            ]));

        let z = Fr::from_repr(
            BigInteger768([
                4187048794430511326,
                4174923059455998596,
                14927629489703980491,
                8395093258707691434,
                5053280345429221948,
                4848362025213177059,
                8755031092797359863,
                17074426890792517234,
                7776812427117708999,
                15813258309609623801,
                11288926818840647596,
                314863372237914,
            ]));

        let null_pk = G1Projective::new(x, y, z);

        Self{null_sig, null_pk}
    }
}



#[test]
fn test_pk_null_gen() {
    use algebra::curves::ProjectiveCurve;
    use crypto_primitives::crh::{
        FixedLengthCRH, pedersen::PedersenWindow,
        bowe_hopwood::{
            BoweHopwoodPedersenCRH, BoweHopwoodPedersenParameters,
        },
    };

    #[derive(Clone)]
    struct PkNullWindow {}
    impl PedersenWindow for PkNullWindow {
        const WINDOW_SIZE: usize = 40;
        const NUM_WINDOWS: usize = 1;
    }

    type H = BoweHopwoodPedersenCRH<G1Projective, PkNullWindow>;
    type P = BoweHopwoodPedersenParameters<G1Projective>;

    fn create_generator(g: G1Projective) -> Vec<Vec<G1Projective>> {
        let mut generators = Vec::new();
        for _ in 0..PkNullWindow::NUM_WINDOWS {
            let mut generators_for_segment = Vec::new();
            let mut base = g.clone();
            for _ in 0..PkNullWindow::WINDOW_SIZE {
                generators_for_segment.push(base);
                for _ in 0..4 {
                    base.double_in_place();
                }
            }
            generators.push(generators_for_segment);
        }
        generators
    }

    let g_x = Fr::from_repr(
        BigInteger768([
            8381012056149863772,
            6373571720928963064,
            8123738198255740872,
            17547733938769215386,
            8139434405735723002,
            6390033263133066995,
            17707973184339470887,
            5421532999015743452,
            8243428001810028012,
            6216251229661443135,
            6398492851397838710,
            346699556869099,
        ]));

    let g_y = Fr::from_repr(
        BigInteger768([
            2704739755736321217,
            2227358269084518834,
            507627046716438172,
            3266935385977024867,
            2157929234018364116,
            7415411989156878858,
            8084092606968360177,
            11127175295366493896,
            15453831365616029897,
            4255424253204237885,
            10139591791938123415,
            435398301079215,
        ]));

    let g_z = Fr::from_repr(
        BigInteger768([
            7224775733907965344,
            12511303325827949109,
            16537146212539739484,
            9047578027698864974,
            1070153754410646309,
            11767631247772359446,
            13462746740642154250,
            633667227403756238,
            2430410092065728298,
            11488882025365391349,
            5975253083675241861,
            96975263659865,
        ]));

    let g = G1Projective::new(g_x, g_y, g_z);
    let preimage_str = "Strontium Sr 90";
    let params = P{generators: create_generator(g)};
    let computed_pk_null = H::evaluate(&params, preimage_str.as_bytes()).unwrap();

    let circuit_params = NaiveThresholdSigParams::new();
    assert_eq!(circuit_params.null_pk, computed_pk_null);
}