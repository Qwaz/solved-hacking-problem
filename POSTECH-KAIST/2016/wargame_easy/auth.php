<?php
  if(!$_SESSION[id]){
	echo "<script>location.href('?page=login');</script>";
	exit();
  }
?>
  <section id="intro" class="intro-section">
        <div class="container">
            <div class="row">
                <div class="col-lg-12">
		  <center>
                    <h1>Auth</h1>
		  <form name="f" method="post" action="?page=auth">
                    <p><input class="form-control" style="color:#000;width:300px;" placeholder="Key" type="text" name="key" /></p>
                    <a class="btn btn-default page-scroll" onclick="f.submit();">Auth</a>
		  </form>
		  <?php
		  if($_POST){
			$key = array('glenngould', 'barenboim', 'zimmerman');
			$point = array(10, 20, 30);
			$i = 0;
			foreach($key as $value){
			  if($value == $_POST[key]) {
				$sql = @mysql_fetch_array(mysql_query("select level".intval($i+1)." from member where id='$_SESSION[id]'"));
				if($sql[0] == "1") {
				  echo "<script>alert('You have already cleared.');history.back(-1);</script>";
				  exit();
				}
				$sql = "update member set point = point + $point[$i] where id = '$_SESSION[id]'";
				$q = @mysql_query($sql);
				$sql2 = "update member set level".intval($i+1)."=1 where id='$_SESSION[id]'";
				$q2 = @mysql_query($sql2);
				$sql3 = "update member set lastauth=$time where id='$_SESSION[id]'";
				$q3 = @mysql_query($sql3);
				echo "<script>alert('Level".intval($i+1)." Clear!');location.href='?page=prob';</script>";
				exit();
			  }
			  $i++;
			}
		  }
		  ?>
		  </center>
                </div>
            </div>
        </div>
    </section>
