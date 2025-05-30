Tra il quarto e il quinto superiore ho seguito delle lezioni di cybersecurity all'università della Sapienza come parte del progetto cyberchallenge (https://cyberchallenge.it/). Visto il grande impatto che questo corso ha avuto sulla mia vita, da cui è nata una nuova passione e nuovi progetti per il futuro, ho deciso di portare come capolavoro un esempio di attività svolta durante il periodo di studio.

Nota: i commenti all'interno del codice sono stati scritti in inglese per attenermi allo standard del corso.


L'attività riportata è una sfida che io e gli altri studenti abbiamo completato individualmente con lo scopo di imparare ad eseguire uno specifico atacco su sistemi crittografici di tipo SPN, nello specifico caso in cui vengano usati esattamente 2 volte sullo stesso messaggio allo scopo di aumentare la sicurezza del cifrario (come nel caso di 2DES).



Spiegazione dell'attacco "Meet in the middle":

Se vogliamo crittare un messaggio usando un cifrario simmetrico come aes o des, tutto quello che dobbiamo fare è scegliere una chiave di lunghezza fissa e usarla insieme all'algoritmo scelto per trasformare un messaggio "plaintext" in "ciphertext", operazione che sarà poi reversibile da un altro algoritmo solo avendo la stessa chiave di cifratura.

Se l'algoritmo scelto è troppo vecchio, però, la chiave richiesta dall'algoritmo potrebbe essere troppo corta e perciò alcuni computer moderni potrebbero essere in grado di provare tutte le chiavi possibili fino a trovare quella che decritta il messaggio (attacco brute force).

In questo caso, per aumentare la sicurezza, possiamo crittare il messaggio una volta con una chiave, scegliere un altra chiave e crittare il chipertext una seconda volta con la seconda chiave.

Adesso un attaccante per eseguire un attacco bruteforce dovrebbe provare a indovinare una combinazione di 2 chiavi diverse, aumentando esponenzialmente il tempo di esecuzione dell'attacco. NO?

SBAGLIATO! Quando si parla di crittografia simmetrica, si parla di usare le stesse chiavi molte volte per crittare e decrittare messaggi diversi, l'obiettivo di un attaccante non è quindi tanto scoprire un singolo messaggio quanto scoprire la chiave usata per crittarlo, in modo da avere accesso a tutti gli altri messaggi della conversazione.

Se l'attaccante avesse accesso ad un plaintext e ad un suo corrispettivo ciphertext, infatti, egli potrebbe mettere in atto il seguente attacco con l'obiettivo di scoprire la coppia di chiavi usate:

- crittare il plaintext con tutte le chiavi possibili, salvandosi tutte le coppie chiave - ciphertext in un dizionario
- decrittare il chipertext con tutte le chiavi possibili, salvandosi tutte le coppie chiave - plaintext in un dizionario
- confrontare i 2 dizionari, e nel caso in cui ci sia un valore comune tra i due, ricavare le chiavi associate a quel valore in entrabi i dizionari: quelle saranno le chiavi usate per crittare il messaggio originale.



Nello specifico caso di questo esercizio, allo studente sono vengono dati a disposizione 3 files da cui ricavare una "flag", ossia un messaggio segreto che una volta ricavato prova che la sfida è stata completata:

- challenge.py: l'implemetazione in python di un algoritmo crittografico spn, vulnerabile inquanto prevede l'utilizzo di due chiavi da 8 bytes l'una, molto poco se consideriamo che ad oggi il minimo è 16 bytes. Le due chiavi sono anche strettamente collegate tra loro per introdurre altra vulnerabilità e facilitare la sfida.

- boxes.py: substitution box e permutation box usate dal sistema spn per sostituire e permutare i bytes del messaggio.

- output.txt: messaggio segreto, risultato della cifratura originale eseguita da challenge.py, che include sia la parte di plaintext visibile in challenge.py e anche la flag non visibile nel file.

Nota: questi 3 files sono stati riportati nella cartell original_files esattamente come erano appena scaricati dal portale della sfida, mentre i files al di fuori della cartella sono di mia produzione o quantomeno modificati a partire dai files originali (escluso boxes.py che deve solo essere importato come modulo).


Ho quindi proceduto a implementare in python una funzione inversa a quella datami dalla sfida modificando il file originale (challenge_patched.py), in modo da essere in grado di decrittare un messaggio crittato con la prima funzione, ma mi sono presto accorto che python è un linguaggio troppo lento per eseguire operazioni di cifratura o decifratura per ogni chiave possibile. Allora ho deciso di reimplementare entrambe le funzioni in go, un linguaggio centinaia di volte più veloce, aggiungendo anche una gestione dei thread per eseguire l'operazione in modo asincrono massimizzando la resa della mia cpu. 
Nota: come riportato nei commenti del codice go, la reimplementazione in delle funzioni di cifratura e decifratura è stata realizzata senza reintegrare la gestione di molteplici blocchi da 8 bytes, visto che crittare e decrittare un solo blocco è sufficiente all'attacco.

Nonostante questo, il tempo di esecuzione massimo dell'attacco era di circa 50 ore (25 ore di media), e chiaramente la sfida non prevedeva che il mio pc eseguisse una tale mole di lavoro, per cui ho riesaminato i file della sfida in cerca di altre vulnerabilità da sfruttare.

Dopo una seconda analisi, ho notato che la s box del file boxes.py era vulnerabile inquanto riporta "1" all'indice 1 dell'array di cui fa parte.
Questo causa all'algoritmo un malfunzionamento per cui qualunque byte inserito all'indice 1 del messaggio originale viene sostituito usando la s box ma mai permutato.

Ho quindi implemetato un piccolo attacco meet in the middle in python (findFixedBytes.py) per attaccare solo quel singolo byte in maniera analoga a come descritto finora, ricavando un centinaio di possibili bytes che fanno parte delle 2 chiavi originali in posizione 1 e riducendo quindi il tempo di esecuzione massimo del grande attacco meet in the middle a circa 6 ore.

Dopo aver modificato il file attack.go per ridurre la mole di lavoro grazie alle nuove informazioni, ho eseguito il programma ricavando la coppia di chiavi finali in circa 2 ore, e creato finaldecrypt.py per trovare il messaggio finale usando le chiavi.

