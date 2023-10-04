#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libssh/libssh.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

#define MAX_ATTEMPTS 3
#define QUEUE_NUM 0 


typedef struct {
char ip[16];
int attempts;
} blacklist_entry;

blacklist_entry *blacklist = NULL;
int blacklist_size = 0;
int blacklist_capacity = 0;

void add_to_blacklist(char *ip) {
// Controlla se l'indirizzo è già nella lista nera
for (int i = 0; i < blacklist_size; i++) {
if (strcmp(blacklist[i].ip, ip) == 0) {
return; // Indirizzo già presente, non fare nulla
}
}
// Controlla se c'è spazio nell'array
if (blacklist_size == blacklist_capacity) {
// Raddoppia la capacità dell'array se necessario
blacklist_capacity = (blacklist_capacity == 0) ? 1 : blacklist_capacity * 2;
// Rialloca l'array con la nuova capacità
blacklist = realloc(blacklist, blacklist_capacity * sizeof(blacklist_entry));
if (blacklist == NULL) {
perror("realloc");
exit(EXIT_FAILURE);
}
}
// Aggiunge il nuovo indirizzo all'array con zero tentativi
strcpy(blacklist[blacklist_size].ip, ip);
blacklist[blacklist_size].attempts = 0;
blacklist_size++;
}

void increment_attempts(char *ip) {
// Cerca l'indirizzo nella lista nera
for (int i = 0; i < blacklist_size; i++) {
if (strcmp(blacklist[i].ip, ip) == 0) {
// Incrementa il numero di tentativi
blacklist[i].attempts++;
// Se il numero di tentativi supera il limite, stampa un messaggio di avviso
if (blacklist[i].attempts > MAX_ATTEMPTS) {
printf("Indirizzo %s ha superato il numero massimo di tentativi falliti\n", ip);
}
return;
}
}
}

int is_blacklisted(char *ip) {
// Cerca l'indirizzo nella lista nera
for (int i = 0; i < blacklist_size; i++) {
if (strcmp(blacklist[i].ip, ip) == 0) {
// Controlla se il numero di tentativi supera il limite
if (blacklist[i].attempts > MAX_ATTEMPTS) {
return 1; // Indirizzo nella lista nera e bloccato
} else {
return 0; // Indirizzo nella lista nera ma non bloccato
}
}
}
return 0; // Indirizzo non nella lista nera
}


void print_blacklist() {
printf("Lista nera:\n");
for (int i = 0; i < blacklist_size; i++) {
printf("%s: %d tentativi\n", blacklist[i].ip, blacklist[i].attempts);
}
}


int try_ssh_connection(char *host, char *user, char *password) {
ssh_session session; // Struttura per memorizzare la sessione SSH
int rc; // Codice di ritorno delle funzioni SSH
int verbosity = SSH_LOG_NOLOG; // Livello di verbosità dei messaggi SSH
int port = 22; // Porta SSH del server remoto

// Crea una nuova sessione SSH
session = ssh_new();
if (session == NULL) {
fprintf(stderr, "Errore nella creazione della sessione SSH\n");
return -1;
}


ssh_options_set(session, SSH_OPTIONS_HOST, host); // Imposta l'host remoto
ssh_options_set(session, SSH_OPTIONS_USER, user); // Imposta l'utente remoto
ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity); // Imposta il livello di verbosità
ssh_options_set(session, SSH_OPTIONS_PORT, &port); // Imposta la porta remota


rc = ssh_connect(session);
if (rc != SSH_OK) {
fprintf(stderr, "Errore nella connessione al server: %s\n", ssh_get_error(session));
ssh_free(session); // Libera la memoria della sessione SSH
return -1;
}


rc = ssh_userauth_password(session, NULL, password);
if (rc != SSH_AUTH_SUCCESS) {
fprintf(stderr, "Errore nell'autenticazione con la password: %s\n", ssh_get_error(session));
ssh_disconnect(session); // Disconnette la sessione SSH dal server
ssh_free(session); // Libera la memoria della sessione SSH
return -1;
}


printf("Connessione SSH riuscita con %s@%s\n", user, host);

// Chiude la sessione SSH
ssh_disconnect(session); // Disconnette la sessione SSH dal server
ssh_free(session); // Libera la memoria della sessione SSH

return 0;
}


static int handle_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
struct nfq_data *nfa, void *data) {
u_int32_t id; // ID del pacchetto
struct nfqnl_msg_packet_hdr *ph; // Header del pacchetto
unsigned char *payload; // Payload del pacchetto
int payload_len; // Lunghezza del payload in byte
char ip[16]; // Indirizzo IP sorgente del pacchetto


ph = nfq_get_msg_packet_hdr(nfa);
if (ph == NULL) {
return -1;
}

id = ntohl(ph->packet_id);

payload_len = nfq_get_payload(nfa, &payload);
if (payload_len < 0) {
return -1;
}

snprintf(ip, 16, "%d.%d.%d.%d", payload[12], payload[13], payload[14], payload[15]);

if (is_blacklisted(ip)) {
printf("Pacchetto proveniente da %s scartato\n", ip);
return nfq_set_verdict(qh, id, NF_DROP, 0, NULL); // Scarta il pacchetto
} else {
return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); // Accetta il pacchetto
}
}