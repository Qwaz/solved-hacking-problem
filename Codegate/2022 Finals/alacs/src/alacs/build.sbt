import scala.scalanative.build._

scalaVersion := "3.1.3"

libraryDependencies += "org.scala-lang.modules" %%% "scala-parser-combinators" % "2.1.1"

nativeConfig ~= {
  _.withMode(Mode.releaseFast)
   .withLTO(LTO.thin)
   .withGC(GC.none)
   .withLinkingOptions(Seq("-no-pie"))
}

enablePlugins(ScalaNativePlugin)
