#include <cstdint>
#include <gmp.h>
#include <gmpxx.h>

#define SECURITY_PARAMETER (1024)

typedef struct
{
    mpz_t p;
    mpz_t q;
    mpz_t n;
    mpz_t e;
    mpz_t d;
} PrivateKey;

typedef struct
{
    mpz_t e;
    mpz_t n;
} PublicKey;

void _get_prime(gmp_randstate_t rstate, mpz_t p, uint32_t n)
{
    mpz_t r;
    mpz_init(r);
    do
    {
        mpz_urandomb(r, rstate, n);
        mpz_setbit(r, n - 1);
        mpz_nextprime(p, r);
    } while (mpz_sizeinbase(p, 2) >= n + 1);
    mpz_clear(r);
}

void generate_keypair(gmp_randstate_t rstate, PublicKey *pub, PrivateKey *priv)
{
    mpz_t phi, pm, qm;
    mpz_inits(phi, pm, qm, NULL);

    /* Generate private key*/
    mpz_inits(priv->p, priv->q, priv->n, priv->e, priv->d, NULL);
    mpz_set_ui(priv->e, 65537UL);
    _get_prime(rstate, priv->p, SECURITY_PARAMETER);
    _get_prime(rstate, priv->q, SECURITY_PARAMETER);
    mpz_mul(priv->n, priv->p, priv->q);
    mpz_sub_ui(pm, priv->p, 1UL);
    mpz_sub_ui(qm, priv->q, 1UL);
    mpz_mul(phi, pm, qm);
    mpz_invert(priv->d, priv->e, phi);

    /* Generate public key */
    mpz_init_set(pub->e, priv->e);
    mpz_init_set(pub->n, priv->n);

    /* Cleanup */
    mpz_clears(phi, pm, qm, NULL);
}

void generate_signature(mpz_t sign, mpz_t m, PrivateKey *priv)
{
    mpz_t sp, sq, qi;
    mpz_init2(sp, SECURITY_PARAMETER);
    mpz_init2(sq, SECURITY_PARAMETER);
    mpz_init2(qi, SECURITY_PARAMETER);

    mpz_powm(sp, m, priv->d, priv->p);
    mpz_powm(sq, m, priv->d, priv->q);
    mpz_invert(qi, priv->q, priv->p);
    mpz_sub(sign, sp, sq);
    mpz_mul(sign, sign, qi);
    mpz_mod(sign, sign, priv->p);
    mpz_mul(sign, sign, priv->q);
    mpz_add(sign, sign, sq);
    mpz_mod(sign, sign, priv->n);

    mpz_clears(sp, sq, NULL);
}

#define TABLE_BITS (20)

int main()
{
    // stdout will go to `./table`
    freopen("table", "w", stdout);

#pragma omp parallel for
    for (unsigned long int seed = 0; seed < (1 << TABLE_BITS); seed++)
    {
        gmp_randstate_t rstate;
        gmp_randinit_lc_2exp_size(rstate, 16);
        gmp_randseed_ui(rstate, seed << (32 - TABLE_BITS));

        mpz_t m, sign;
        PrivateKey priv;
        PublicKey pub;

        mpz_inits(m, sign, NULL);

        generate_keypair(rstate, &pub, &priv);
        mpz_urandomb(m, rstate, SECURITY_PARAMETER);
        generate_signature(sign, m, &priv);

#pragma omp critical
        gmp_printf("%d %Zx %Zx %Zx\n", seed, pub.n, m, sign);

        mpz_clears(m, sign, NULL);
    }

    return 0;
}
