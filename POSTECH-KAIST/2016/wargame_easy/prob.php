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
                    <h1>Prob</h1>
		  <?php
		  $point = array(10, 20, 30);
		  $i = 0;
		  foreach($point as $value){
			$sql = @mysql_fetch_array(mysql_query("select level".intval($i+1)." from member where id='$_SESSION[id]'"));
			if($sql[0] == "1")
			  echo "<p><a class='btn btn-default page-scroll' onclick='location.href=\"?page=level".intval($i+1)."\"'>Clear</a></p>";
			else
			  echo "<p><a class='btn btn-default page-scroll' onclick='location.href=\"?page=level".intval($i+1)."\"'>Level ".intval($i+1)." (".$value."pt)</a></p>";
			$i++;
		  }
		  ?>
		  </center>
                </div>
            </div>
        </div>
    </section>
