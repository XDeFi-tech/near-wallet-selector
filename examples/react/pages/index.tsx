import type { NextPage } from "next";
import { Fragment, useState } from "react";
import { WalletSelectorContextProvider } from "../contexts/WalletSelectorContext";
import Content from "../components/Content";
import { ImportAccountSelectorContextProvider } from "../contexts/WalletSelectorImportContext";
import ImportContent from "../components/ImportContent";

const Home: NextPage = () => {
  const [showImport, setShowImport] = useState<boolean>(false);

  return (
    <Fragment>
      <div className="title-container">
        <h1>{showImport ? "Import Account" : "NEAR Guest Book"}</h1>
        <button onClick={() => setShowImport(!showImport)}>
          {showImport ? "Back to Log in" : "Try Import"}
        </button>
      </div>
      {showImport ? (
        <ImportAccountSelectorContextProvider>
          <ImportContent />
        </ImportAccountSelectorContextProvider>
      ) : (
        <WalletSelectorContextProvider>
          <Content />
        </WalletSelectorContextProvider>
      )}
    </Fragment>
  );
};

export default Home;
