<?php
  if(!$_SESSION[id]){
	echo "<script>location.href('?page=login');</script>";
	exit();
  }
  $sql = @mysql_fetch_array(mysql_query("select pw,point from member where id='$_SESSION[id]'"));
?>
  <section id="intro" class="intro-section">
        <div class="container">
            <div class="row">
                <div class="col-lg-12">
		  <center>
                    <h1>Info</h1>
		  <h2><?php echo $_SESSION[id]." ".$sql[point]."pts"; ?></h2>
		  <form name="f" method="post" action="?page=info">
                    <p><input class="form-control" style="color:#000;width:300px;" placeholder="<?php echo $sql[pw]; ?>" type="text" name="pw" /></p>
                    <a class="btn btn-default page-scroll" onclick="f.submit();">Change PW</a>
		  </form>
		  <?php
		  if($_POST){
			if($_SESSION[id] == 'admin') exit();
			if($_POST[pw] == ""){
			  echo "<script>alert('Input your password.');history.go(-1);</script>";
			  exit();
			}
			if(strlen($_POST[pw]) > 32){
			  echo "<script>alert('Can't create password bigger than 32 bytes.');history.go(-1);</script>";
			  exit();
			}
			$_POST[pw] = addslashes($_POST[pw]);
			$sql = "update member set pw = '$_POST[pw]' where id = '$_SESSION[id]'";
			$q = @mysql_query($sql);
			echo "<script>alert('PW Changed.');location.href='?page=info';</script>";
		  }
		  ?>
		  </center>
                </div>
            </div>
        </div>
    </section>
