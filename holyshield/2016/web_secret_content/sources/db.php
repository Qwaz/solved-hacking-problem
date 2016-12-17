<?php
class dbClass{
	var $conn = null;
	var $stmt = null;

	function __construct(){
		if($this->conn == null){
			$this->connect();
		}
	}

	function connect(){
		global $conHost, $conDB, $conId, $conPw;
		$conInfo = "mysql:host=" . $conHost . ";dbname=" . $conDB . ";charset=utf8";
		$this->conn = new PDO($conInfo, $conId, $conPw);
	}

	function query($query, $param = array()){
		$pdo = $this->conn;
		$stmt = $pdo->prepare($query);
		$stmt->execute($param);
		$this->stmt = $stmt;
	}

	function getRows($query, $param = array()){
		$this->query($query, $param);
		return $this->stmt->fetchAll(PDO::FETCH_ASSOC);
	}

	function __destruct(){
		$this->stmt = null;
		$this->conn = null;
	}
}
?>
