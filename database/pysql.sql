-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Creato il: Dic 20, 2024 alle 17:09
-- Versione del server: 10.4.32-MariaDB
-- Versione PHP: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `pysql`
--

-- --------------------------------------------------------

--
-- Struttura della tabella `accessii`
--

CREATE TABLE `accessii` (
  `id` int(11) NOT NULL,
  `Utente` varchar(20) DEFAULT NULL,
  `Password` varchar(10) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dump dei dati per la tabella `accessii`
--

INSERT INTO `accessii` (`id`, `Utente`, `Password`) VALUES
(1, 'Sara12', 'Ci1.sa'),
(2, 'alexrp', 'jlsùç8'),
(3, 'marias', '148é-kidj'),
(4, 'marcosp', '452?òa<'),
(5, 'alessiap', 'djsòs96-ò'),
(6, 'chiaraver', 'djfhkl-.àD'),
(7, 'vincenzo', '123456');

-- --------------------------------------------------------

--
-- Struttura della tabella `registrazioni`
--

CREATE TABLE `registrazioni` (
  `id` int(11) NOT NULL,
  `Nome` varchar(20) DEFAULT NULL,
  `Cognome` varchar(20) DEFAULT NULL,
  `Email` char(50) DEFAULT NULL,
  `Nome_Utente` varchar(20) DEFAULT NULL,
  `Password_Utente` varchar(10) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dump dei dati per la tabella `registrazioni`
--

INSERT INTO `registrazioni` (`id`, `Nome`, `Cognome`, `Email`, `Nome_Utente`, `Password_Utente`) VALUES
(1, 'chiara', 'verdi', '', 'chiaraver', 'djfhkl-.àD');

-- --------------------------------------------------------

--
-- Struttura della tabella `richieste`
--

CREATE TABLE `richieste` (
  `id` int(11) NOT NULL,
  `metodo` varchar(10) NOT NULL,
  `url` text NOT NULL,
  `parametri` text NOT NULL,
  `risultati` text NOT NULL,
  `timestamp` date NOT NULL,
  `utente_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dump dei dati per la tabella `richieste`
--

INSERT INTO `richieste` (`id`, `metodo`, `url`, `parametri`, `risultati`, `timestamp`, `utente_id`) VALUES
(1, 'GET', 'http://localhost:5000/search', 'ImmutableMultiDict([(\'query\', \"<script>alert(\'XSS\')</script>\")])', 'XSS rilevata', '2024-12-11', 1),
(5, 'GET', 'http://localhost:5000/login', 'ImmutableMultiDict([(\'username\', \"admin\' OR \'1\'=\'1\")])', 'SQL Injection rilevata', '2024-12-20', 1),
(6, 'GET', 'http://localhost:5000/user', 'ImmutableMultiDict([(\'id\', \'1 UNION SELECT username, password FROM users\')])', 'SQL Injection rilevata', '2024-12-20', 1),
(7, 'GET', 'http://localhost:5000/profile', 'ImmutableMultiDict([(\'name\', \'<img src=\"x\" onerror=\"alert(\\\'XSS\\\')\">\')])', 'XSS rilevata', '2024-12-20', 1);

--
-- Indici per le tabelle scaricate
--

--
-- Indici per le tabelle `accessii`
--
ALTER TABLE `accessii`
  ADD PRIMARY KEY (`id`);

--
-- Indici per le tabelle `registrazioni`
--
ALTER TABLE `registrazioni`
  ADD PRIMARY KEY (`id`);

--
-- Indici per le tabelle `richieste`
--
ALTER TABLE `richieste`
  ADD PRIMARY KEY (`id`),
  ADD KEY `accessoreport` (`utente_id`);

--
-- AUTO_INCREMENT per le tabelle scaricate
--

--
-- AUTO_INCREMENT per la tabella `accessii`
--
ALTER TABLE `accessii`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- AUTO_INCREMENT per la tabella `registrazioni`
--
ALTER TABLE `registrazioni`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT per la tabella `richieste`
--
ALTER TABLE `richieste`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- Limiti per le tabelle scaricate
--

--
-- Limiti per la tabella `richieste`
--
ALTER TABLE `richieste`
  ADD CONSTRAINT `accessoreport` FOREIGN KEY (`utente_id`) REFERENCES `accessii` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
