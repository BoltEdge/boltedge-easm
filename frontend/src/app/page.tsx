import Navbar from '@/components/Navbar';
import Hero from '@/components/Hero';
import Products from '@/components/Products';
import EasmSpotlight from '@/components/EasmSpotlight';
import SecToolkitSpotlight from '@/components/SecToolkitSpotlight';
import WhyBoltEdge from '@/components/WhyBoltEdge';
import Metrics from '@/components/Metrics';
import CtaBand from '@/components/CtaBand';
import Footer from '@/components/Footer';

export default function Home() {
  return (
    <>
      <Navbar />
      <main>
        <Hero />
        <Products />
        <EasmSpotlight />
        <SecToolkitSpotlight />
        <WhyBoltEdge />
        <Metrics />
        <CtaBand />
      </main>
      <Footer />
    </>
  );
}
