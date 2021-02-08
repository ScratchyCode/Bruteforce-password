// Coded by Scratchy
/*
Compilare con: gcc bruteforce_sha256.c -lm -pthread -lssl -lcrypto -O2 -o brute
ed eseguire provando: ./brute 569428c3f4cf6ccde2ff97a7646733d1ee0fd77f1dfed45a16c79940f3dca862
con 4 char
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>
#include <sched.h>
#include <openssl/sha.h>

#define CORE 8        // il numero di core da usare deve essere tale che: sizeof(charset) % CORE == 0

/*
commentare una di queste stringhe se si conoscono informazioni aggiuntive sulla passwd
(tipo sapendo che non contiene numeri non bisogna usarli)
se si cambia il charset deve essere scelto in modo che sizeof(charset) % CORE == 0
*/
const char charset_global[] =
"abcdefghijklmnopqrstuvwxyz"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"0123456789"
"_.-!@*$?&%"
;

// struttura dati passata ai thread
struct struttura{
    int lenPasswd;
    int numFile;
    int elementi;
    int splitCharsetInizio;
    const unsigned char *charset_local;
    unsigned char *hash;
};

void *parallela(void *parametri);
void checkPtr(void *ptr);
void print_affinity();
char *StringHashToCharArray(const char *s);
int match(char *enc, char *hash);

int main(int argc, char **argv){
    char *hash = StringHashToCharArray(argv[1]);
    int tmp;
    
    // eseguire come root per avere questa impostazione
    tmp = nice(-20); // lol
    
    int i, n, elementi=strlen(charset_global);
    int nbin = (int)(elementi/CORE);                // numero di elementi per bin
    int bin = (int)(elementi/nbin);                 // numero di bin che dividono il charset
    int inizio;                                     // indice numerico per dividere il charset in bin
    
    struct struttura *threadsMem = malloc(bin * sizeof(struct struttura));
    checkPtr(threadsMem);
    
    // sicurezza per l'affinità dell'esecuzione dei thread sui core specificati
	cpu_set_t bitmask;
	
	printf("Core disponibili:\t");
	print_affinity();
	
	CPU_ZERO(&bitmask);
	
    for(i=0; i<CORE; i++){
        CPU_SET(i,&bitmask);
        
        if(sched_setaffinity(0,sizeof(cpu_set_t),&bitmask) == -1){
            perror("sched_setaffinity");
            assert(false);
        }
    }
    
    printf("Core settati:\t\t");
    print_affinity();
    
    printf("\nInserire la lunghezza della password da provare: ");
    tmp = scanf("%d",&n);
    
    fprintf(stderr,"Calcolo in corso...");
    
    // riempo ogni struttura con le informazioni sul thread corrispondente
    inizio = 0;
    for(i=0; i<bin; i++){
        threadsMem[i].lenPasswd = n;
        threadsMem[i].numFile = i + 1;
        threadsMem[i].elementi = elementi;
        threadsMem[i].splitCharsetInizio = inizio;
        threadsMem[i].charset_local = charset_global;
        threadsMem[i].hash = hash;
        inizio = inizio + nbin;
    }    
    
	// inizializzo un array di thread e li eseguo parallelamente al main
	pthread_t *thread = malloc(bin * sizeof(pthread_t));
	checkPtr(thread);
    
	for(i=0; i<bin; i++){
	    pthread_create(&thread[i],NULL,parallela,&threadsMem[i]);
    }
    
	// aspetto la fine di tutti i thread
	for(i=0; i<bin; i++){
	    pthread_join(thread[i],NULL);
	}
    
    printf("\nPassword non trovata.\n");
    
    free(threadsMem);
    free(thread);
    
    return 0;
}


void *parallela(void *parametri){
    /*** DATI PER IL THREAD ***/
    struct struttura *dati = (struct struttura *) parametri;
    int n = dati->lenPasswd;                    // n char della passwd
    int numeroFile = dati->numFile;             // nome file su cui opera il singolo thread
    int elementi = dati->elementi;              // elementi presenti nel charset
    int inizio = dati->splitCharsetInizio;      // valore di inizio con cui settare l'array mask
    const char *charset = dati->charset_local;  // copia del charset per non creare colli di bottiglia
    char *enc = dati->hash;                     // copia dell'hash da decifrare
    
    /*** VARIABILI PER IL CALCOLO ***/
    int i, j;
    bool uscita = 0;                                        // flag per condizione di terminazione
    int nbin = (int)(elementi/CORE);                        // numero di elementi per bin
    int bin = (int)(elementi/nbin);                         // numero di bin che dividono il charset
    unsigned long long int progresso = 0;                   // percentuale dei calcoli svolti
    long double lavoro = pow(elementi,n);                   // stima dei calcoli da eseguire
    char *password = calloc(n,sizeof(char));                // stringa per salvare la pass provata ad ogni giro del while
    char *hash = calloc(SHA256_DIGEST_LENGTH,sizeof(char));
    checkPtr(password);
    checkPtr(hash);
    
    /*
    mask è una maschera numerica che rappresenta la passwd da brutare;
    i valori numerici fungono da indici di scorrimento sul charset
    */
    int *mask = calloc(n,sizeof(int));
    checkPtr(mask);
    
    mask[0] = inizio;
    for(i=1; i<n; i++){
        mask[i] = 0;
    }
    
    // calcolo
    while(1){
        // flag per concludere il calcolo
        uscita = 1;
        
        // printa una stima percentuale dei calcoli eseguiti; commentare per velocizzare il lavoro
        //fprintf(stderr,"\rTHREAD_WORK_%d:\t\t%d * %.1f%%",numeroFile,CORE,(float)(progresso*100./lavoro));
        
        // print di una passwd
        for(i=0; i<n; i++){
            password[i] = charset[mask[i]];
            
            // non esco finchè mask non ha assunto tutti i valori del charset,
            // senza però sconfinare in altri bin
            if(mask[i] < (elementi-1) && mask[0] < inizio+nbin){
                uscita = 0;
            }
        }
        
        // genero l'hash e vedo se combacia con l'hash da brutare;
        // in caso printo la passwd e l'hash corrispondente
        SHA256(password,n,hash);
        if(match(enc,hash)){
            fprintf(stderr,"\nPassword = %s\n",password);
            exit(0);
        }
        
        // valuto la condizione di terminazione
        if(uscita){
            break;
        }
        
        /*
        incremento l'ultima lettera della passwd fino a quando non raggiungo l'ultimo elemento del charset
        per essere printata alla prossima esecuzione del for
        */
        ++mask[n-1];
        
        /*
        controllo e reset della maschera;
        se l'elemento j-esimo di mask ha raggiunto il valore massimo selezionabile allora viene resettato
        per ricominciare a selezionare dal charset il primo elemento, poi viene incrementato l'elemento precedente
        */
        for(j=n-1; j>=1; j--){
            if(mask[j] >= elementi){
                mask[j] = 0;
                ++mask[j-1];
            }
        }
        
        // incrementa la percentuale del lavoro fatto dal thread
        //progresso++;
    }
    
    free(mask);
    free(password);
	
	return NULL;
}

void checkPtr(void *ptr){
    
    if(ptr == NULL){
        perror("\nERROR");
        fprintf(stderr,"\n");
        exit(0);
    }
}

void print_affinity(){
    cpu_set_t bitmask;
    long nproc, i;

    if(sched_getaffinity(0,sizeof(cpu_set_t),&bitmask) == -1){
        perror("sched_getaffinity");
        assert(false);
    }
    
    nproc = sysconf(_SC_NPROCESSORS_ONLN);
    
    for(i=0; i<nproc; i++){
        printf("%d ",CPU_ISSET(i,&bitmask));
    }
    
    printf("\n");
}

char *StringHashToCharArray(const char *s){
    int i;
	char *hash = (char *) malloc(32);
	char two[3];
	
	two[2] = 0;
	for(i=0; i<32; i++){
		two[0] = s[i * 2];
		two[1] = s[i * 2 + 1];
		hash[i] = (char)strtol(two,0,16);
	}
	
	return hash;
}

int match(char *enc, char *hash){
    int i;
    
    for(i=0; i<SHA256_DIGEST_LENGTH; i++){
        if(enc[i] != hash[i]){
            return 0;
        }
    }
    
    // se non ci sono differenze ha trovato la password
    return 1;
}
