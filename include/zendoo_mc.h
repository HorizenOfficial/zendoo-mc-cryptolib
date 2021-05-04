#ifndef ZENDOO_MC_INCLUDE_H_
#define ZENDOO_MC_INCLUDE_H_

#include <stdint.h>
#include <stdlib.h>

static const size_t SC_PROOF_SIZE = 771;
static const size_t SC_VK_SIZE = 1544;
static const size_t SC_FIELD_SIZE = 96;
static const size_t SC_FIELD_SAFE_SIZE = 94;

extern "C" {

#ifdef WIN32
    typedef uint16_t path_char_t;
#else
    typedef uint8_t path_char_t;
#endif

/* Note: Functions panic if input pointers are NULL.*/

//Field related functions

    typedef struct field field_t;

    /* Get the number of bytes needed to serialize/deserialize a field. */
    size_t zendoo_get_field_size_in_bytes(void);

    /*
     * Serialize a field into `field_bytes` given an opaque pointer `field` to it.
     * It's caller's responsibility to ensure that `field_bytes` size is equal to the one
     * returned by `zendoo_get_field_size_in_bytes`. Panic if serialization was
     * unsuccessful.
     */
    void zendoo_serialize_field(
        const field_t*  field,
        unsigned char*  field_bytes
    );

    /*
     * Deserialize a field from `field_bytes` and return an opaque pointer to it.
     * It's caller's responsibility to ensure that `field_bytes` size is equal to the one
     * returned by `zendoo_get_field_size_in_bytes`. Return NULL if deserialization fails.
     */
    field_t* zendoo_deserialize_field(const unsigned char* field_bytes);

    /*
     * Free the memory from the field pointed by `field`. It's caller responsibility
     * to set `field` to NULL afterwards. If `field` was already null, the function does
     * nothing.
     */
    void zendoo_field_free(field_t* field);

//SC SNARK related functions

    typedef struct backward_transfer{
      unsigned char pk_dest[20];
      uint64_t amount;
    } backward_transfer_t;

    typedef struct sc_proof sc_proof_t;

    /* Get the number of bytes needed to serialize/deserialize a sc_proof. */
    size_t zendoo_get_sc_proof_size_in_bytes(void);

    /*
     * Serialize a sc_proof into `sc_proof_bytes` given an opaque pointer `sc_proof` to it.
     * It's caller's responsibility to ensure that `sc_proof_bytes` size is equal to the one
     * returned by `zendoo_get_sc_proof_size_in_bytes`. Panic if serialization was unsuccessful
     */
    void zendoo_serialize_sc_proof(
        const sc_proof_t* sc_proof,
        unsigned char* sc_proof_bytes
    );

    /*
     * Deserialize a sc_proof from `sc_proof_bytes` and return an opaque pointer to it.
     * It's caller's responsibility to ensure that `sc_proof_bytes` size is equal to the one
     * returned by `zendoo_get_sc_proof_size_in_bytes`. If `enforce_membership` flag is set, group membership
     * test for curve points will be performed. Panic if deserialization fails or validity checks fail.
     */
    sc_proof_t* zendoo_deserialize_sc_proof(
        const unsigned char* sc_proof_bytes,
        bool enforce_membership
    );

    /*
     * Free the memory from the sc_proof pointed by `sc_proof`. It's caller responsibility
     * to set `sc_proof` to NULL afterwards. If `sc_proof` was already NULL, the function does
     * nothing.
     */
    void zendoo_sc_proof_free(sc_proof_t* sc_proof);

    typedef struct sc_vk sc_vk_t;

    /* Get the number of bytes needed to serialize/deserialize a sc_vk. */
    size_t zendoo_get_sc_vk_size_in_bytes(void);

    /* Deserialize a sc_vk from a file at path `vk_path` and return an opaque pointer to it.
     * If `enforce_membership` flag is set, group membership test for curve points will be performed.
     * Return NULL if the file doesn't exist, if deserialization fails or validity checks fail.
     */
    sc_vk_t* zendoo_deserialize_sc_vk_from_file(
        const path_char_t* vk_path,
        size_t vk_path_len,
        bool enforce_membership
    );

    /*
     * Deserialize a sc_vk from `sc_vk_bytes` and return an opaque pointer to it.
     * It's caller's responsibility to ensure that `sc_vk_bytes` size is equal to the one
     * returned by `zendoo_get_sc_vk_size_in_bytes`. If `enforce_membership` flag is set, group membership
     * test for curve points will be performed. Panic if deserialization fails or validity checks fail.
     */
    sc_vk_t* zendoo_deserialize_sc_vk(
        const unsigned char* sc_vk_bytes,
        bool enforce_membership
    );

    /*
     * Free the memory from the sc_vk pointed by `sc_vk`. It's caller responsibility
     * to set `sc_vk` to NULL afterwards. If `sc_vk` was already null, the function does
     * nothing.
     */
    void zendoo_sc_vk_free(sc_vk_t* sc_vk);


    /*  Verify a sc_proof given an opaque pointer `sc_proof` to it, an opaque pointer
     *  to the verification key `sc_vk` and all the data needed to construct
     *  proof's public inputs. Returns `true` if proof verification was
     *  successful, false otherwise, panic if some error occured. NOTE: `constant`,
     *  `proofdata` and 'bt_list' can be NULL.
     */
    bool zendoo_verify_sc_proof(
        const unsigned char* end_epoch_mc_b_hash,
        const unsigned char* prev_end_epoch_mc_b_hash,
        const backward_transfer_t* bt_list,
        size_t bt_list_len,
        uint64_t quality,
        const field_t* constant,
        const field_t* proofdata,
        const sc_proof_t* sc_proof,
        const sc_vk_t* sc_vk
    );

//Poseidon hash related functions

    typedef struct poseidon_hash poseidon_hash_t;

    /*
     * Gets a new instance of poseidon_hash. It's possible to customize the initial Poseidon state
     * given a vector of field elements as `personalization`; this is not mandatory and `personalization` can
     * be NULL.
     */
    poseidon_hash_t* zendoo_init_poseidon_hash(
        const field_t** personalization,
        size_t personalization_len
    );

    /*
     * Updates `digest` with a new field element `fe`.
     * NOTE: The function will perform a copy of the FieldElement pointed by `fe` in order to store
     * it as its internal state, therefore it's possible to free `fe` immediately afterwards.
     */
    void zendoo_update_poseidon_hash(const field_t* fe, poseidon_hash_t* digest);

    /*
     * Returns the final digest.
     * NOTE: This method is idempotent, and calling it multiple times will give the same result.
     * It's also possible to `update` with more inputs in between.
     */
    field_t* zendoo_finalize_poseidon_hash(const poseidon_hash_t* digest);

    /*
     * Restore digest to its initial state, allowing to change `personalization` too if needed.
     */
    void zendoo_reset_poseidon_hash(
        poseidon_hash_t* digest,
        const field_t** personalization,
        size_t personalization_len
    );

    /*
     * Free the memory from the poseidon_hash pointed by `digest`.
     * It's caller responsibility to set `digest` to NULL afterwards.
     * If `digest` was already null, the function does nothing.
     */
    void zendoo_free_poseidon_hash(poseidon_hash_t* digest);

    /*
     *   Support struct to enhance and make easier the usage of poseidon_hash, by
     *   making poseidon_hash a member of the struct and wrapping the functions
     *   above. Note the definition of the destructor: when an instance of this struct
     *   will go out of scope, the memory Rust-side will be automatically freed.
     */
    struct ZendooPoseidonHash {
        poseidon_hash_t* digest;

        ZendooPoseidonHash(){
            digest = zendoo_init_poseidon_hash(NULL, 0);
        }

        ZendooPoseidonHash(const field_t** personalization, size_t personalization_len){
            digest = zendoo_init_poseidon_hash(personalization, personalization_len);
        }

        void update(const field_t* fe) {
            zendoo_update_poseidon_hash(fe, digest);
        }

        field_t* finalize(){
            return zendoo_finalize_poseidon_hash(digest);
        }

        void reset(const field_t** personalization, size_t personalization_len) {
            zendoo_reset_poseidon_hash(digest, personalization, personalization_len);
        }

        ~ZendooPoseidonHash() {
            zendoo_free_poseidon_hash(digest);
        }
    };

    /*
     * Compute the Poseidon Hash of a list of field elements `input` of len `input_len`,
     * passed as a list of opaque pointers. Returns an opaque pointer to the hash output
     * or NULL if some error occurred.
     */
    field_t* zendoo_compute_poseidon_hash(
        const field_t** input,
        size_t input_len
    )__attribute__((deprecated("Use ZendooPoseidonHash instead")));

// Merkle Path related functions

    typedef struct ginger_merkle_path ginger_merkle_path_t;

    /*
     * Verify the Merkle Path `path` from `leaf' to `root` for a Merkle Tree of height `height`
     */
    bool zendoo_verify_ginger_merkle_path(
        const ginger_merkle_path_t* path,
        size_t height,
        const field_t* leaf,
        const field_t* root
    );

    /*
     * Free the memory from the Ginger Merkle Path pointed by `path`.
     * It's caller responsibility to set `path` to NULL afterwards.
     * If `path` was already null, the function does nothing.
     */
    void zendoo_free_ginger_merkle_path(ginger_merkle_path_t* path);


//Poseidon-based Merkle Tree related functions

    typedef struct ginger_mht ginger_mht_t;

    /*
     * Gets a new instance of a Ginger Merkle Tree, of height `height`.
     * `processing_step` is used to tune the memory usage of the tree.
     * In particular, `processing_step` defines the number of leaves to
     * store before triggering the computation of the root.
     * Decreasing `processing_step` leads to less memory consumption but
     * significantly worsen performances, as the computation of the root is
     * triggered more often; conversely, increasing `processing_step` increases
     * the memory usage too but improves performances.
     * Meaningful values for `processing_step` are between 1 (i.e. update the root
     * at each leaf), leading to best memory efficiency but worse performances, and
     * the maximum number of leaves (or the mean number of leaves you plan to add),
     * leading to worse memory efficiency but best performances (root is computed
     * just once, but all the leaves must be kept in memory).
     */
    ginger_mht_t* zendoo_new_ginger_mht(size_t height, size_t processing_step);

    /*
     * Appends `leaf` to `tree`.
     * NOTE: The function will perform a copy of the FieldElement pointed by `leaf` in order to store
     * it as its internal state, therefore it's possible to free `leaf` immediately afterwards.
     */
    void zendoo_append_leaf_to_ginger_mht(const field_t* leaf, ginger_mht_t* tree);

    /*
     * This function finalizes the computation of the Merkle tree and returns an updated
     * copy of it. This method is idempotent, and calling it multiple times will
     * give the same result. It's also possible to `update` with more inputs in between.
     */
    ginger_mht_t* zendoo_finalize_ginger_mht(const ginger_mht_t* tree);

    /*
     * This function finalizes the computation of the Merkle tree
     * Once this function is called, it is not possible to further update the tree.
     */
    void zendoo_finalize_ginger_mht_in_place(ginger_mht_t* tree);

    /*
     * Returns the root of the Merkle Tree. This function must be called on a finalized tree.
     * If not, the function returns null.
     */
    field_t* zendoo_get_ginger_mht_root(const ginger_mht_t* tree);

    /*
     * Returns the path from the leaf at `leaf_index` to the root of `tree`.
     */
    ginger_merkle_path_t* zendoo_get_ginger_merkle_path(
        const ginger_mht_t* tree,
        size_t leaf_index
    );

    /*
     * Returns the value of a node at height h assuming that all its children
     * are recursively empty, starting from a pre-defined empty leaf.
     */
    field_t* zendoo_get_ginger_empty_node(size_t height);

    /*
     * Restores the tree to its initial state.
     */
    void zendoo_reset_ginger_mht(ginger_mht_t* tree);

    /*
     * Free the memory from the Ginger Random Access Merkle Tree pointed by `tree`.
     * It's caller responsibility to set `tree` to NULL afterwards.
     * If `tree` was already null, the function does nothing.
     */
    void zendoo_free_ginger_mht(ginger_mht_t* tree);

    /*
     *   Support struct to enhance and make easier the usage of ginger_mht, by
     *   making ginger_mht a member of the struct and wrapping the functions
     *   above. Note the definition of the destructor: when an instance of this struct
     *   will go out of scope, the memory Rust-side will be automatically freed.
     */
    struct ZendooGingerMerkleTree {
        ginger_mht_t* tree;

        ZendooGingerMerkleTree(ginger_mht_t* tree): tree(tree) {}

        ZendooGingerMerkleTree(size_t height, size_t processing_step){
            tree = zendoo_new_ginger_mht(height, processing_step);
        }

        void append(const field_t* leaf) {
            zendoo_append_leaf_to_ginger_mht(leaf, tree);
        }

        ZendooGingerMerkleTree finalize(){
            return ZendooGingerMerkleTree(zendoo_finalize_ginger_mht(tree));
        }

        void finalize_in_place(){
            zendoo_finalize_ginger_mht_in_place(tree);
        }

        field_t* root(){
            return zendoo_get_ginger_mht_root(tree);
        }

        ginger_merkle_path_t* get_merkle_path(size_t leaf_index) {
            return zendoo_get_ginger_merkle_path(tree, leaf_index);
        }

        void reset(){
            zendoo_reset_ginger_mht(tree);
        }

        static field_t* get_empty_node(size_t height) {
            return zendoo_get_ginger_empty_node(height);
        }

        ~ZendooGingerMerkleTree() {
            zendoo_free_ginger_mht(tree);
        }
    };

//Test functions

    /* Deserialize a sc_proof from a file at path `proof_path` and return an opaque pointer to it.
     * If `enforce_membership` flag is set, group membership test for curve points will be performed.
     * Return NULL if the file doesn't exist, if deserialization fails or validity checks fail.
     */
    sc_proof_t* zendoo_deserialize_sc_proof_from_file(
        const path_char_t* proof_path,
        size_t proof_path_len,
        bool enforce_membership
    );

    /* Generates and saves at specified path params_dir the proving key and verification key for MCTestCircuit */
    bool zendoo_generate_mc_test_params(
        const path_char_t* params_dir,
        size_t params_dir_len
    );

    /* Generates, given the required witnesses and the proving key, a MCTestCircuit proof, and saves it at specified path */
    bool zendoo_create_mc_test_proof(
        const unsigned char* end_epoch_mc_b_hash,
        const unsigned char* prev_end_epoch_mc_b_hash,
        const backward_transfer_t* bt_list,
        size_t bt_list_len,
        uint64_t quality,
        const field_t* constant,
        const path_char_t* pk_path,
        size_t pk_path_len,
        const path_char_t* proof_path,
        size_t proof_path_len
    );

    /* Get an opaque pointer to a random field element */
    field_t* zendoo_get_random_field(void);

    /* Get a field element given `value` */
    field_t* zendoo_get_field_from_long(uint64_t value);

    /* Return `true` if the fields pointed by `field_1` and `field_2` are
     * equal, and `false` otherwise.
     */
    bool zendoo_field_assert_eq(
        const field_t* field_1,
        const field_t* field_2
    );

    /* Return `true` if the vks pointed by `sc_vk_1` and `sc_vk_2` are
     * equal, and `false` otherwise.
     */
    bool zendoo_sc_vk_assert_eq(
        const sc_vk_t* sc_vk_1,
        const sc_vk_t* sc_vk_2
    );
}

#endif // ZENDOO_MC_INCLUDE_H_