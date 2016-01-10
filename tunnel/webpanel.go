package tunnel

const _TPL_WEBPANEL = `<!DOCTYPE html>
<html>
 <head> 
  <title>deblocus</title> 
  <style>
body {
    font-family: 'Segoe UI',Arial,'Microsoft Yahei',sans-serif;
    font-size: 87.5%;
}
.container {
	margin: 0 auto;
    max-width: 850px;
    padding: 0 30px;
    width: 90%;
}
.header-container{
	height: 5em;
	line-height: 5em;
	position: relative;
	border-bottom: 1px solid #eee;
	margin-bottom: 2em;
}
.version-container{
	position: absolute;
	line-height: 1em;
	top: 2em;
	right: 2em;
}
.status-container{
	line-height: 2em;
}
span.field{
	display: inline-block;
	width: 12em;
}
</style> 
 </head> 
 <body> 
  <div class="container"> 
   <div class="header-container"> 
    <h1>deblocus client</h1> 
    <div class="version-container">
      {{.Version}} 
    </div> 
   </div> 
   <div class="status-container"> 
    <div class="status-line"> 
     <span class="field">Start Time:</span> {{.StartTime}} 
    </div> 
    <div class="status-line"> 
     <span class="field">Current Status:</span> {{if .Ready}}Online{{else}}Offline{{end}} {{.Connection}} 
    </div> 
    <div class="status-line"> 
     <span class="field">Current Latency:</span> {{.AvgRtt}} 
    </div> 
    <div class="status-line"> 
     <span class="field">Served Requests:</span> {{.ReqCount}} 
    </div> 
    <div class="status-line"> 
     <span class="field">Offline Count:</span> {{.Round}} 
    </div> 
   </div> 
  </div>  
 </body>
</html>`
