import React from "react";
import { Navbar } from "./components/Navbar";
import { BrowserRouter, Route, Routes, Navigate, useLocation } from "react-router-dom";
import { Dashboard } from "./pages/Dashboard";
import { Authentication } from "./components/LoginSignup";
import { RecoilRoot } from 'recoil';
import createStore from 'react-auth-kit/createStore';
import AuthProvider from 'react-auth-kit';
import useIsAuthenticated from 'react-auth-kit/hooks/useIsAuthenticated';
import useAuthHeader from 'react-auth-kit/hooks/useAuthHeader';
import ProtectedRoute from './components/ProtectedRoute';

import HelpRequests from "./components/HelpRequest";
import Forum from "./components/Forums";
import Cards from "./components/Cards";
import AdvancedSearch from "./components/SearchOptions";
import ChatWithFriend from "./components/chatwithfriend";
import HomeTab from "./components/Home/Home";
import { Toaster } from "sonner";
import { Startups } from "./pages/Startups";

const store = createStore({
  authName: '_auth',
  authType: 'cookie',
  cookieDomain: window.location.hostname,
  cookieSecure: false,
});

function AppWrapper() {
  return (
    <RecoilRoot>
      <AuthProvider store={store}>
        <BrowserRouter>
        <Toaster position="top-right"/>
          <App />
        </BrowserRouter>
      </AuthProvider>
    </RecoilRoot>
  );
}

function App() {
  const location = useLocation();
  const isAuthPage = location.pathname === '/login' || location.pathname === '/signup' || location.pathname === '/';
  const isAuth = useIsAuthenticated();
  const authHeader = useAuthHeader();

  return (
    <>
      {<Navbar />}
      {/* <HelpRequests /> */}
      <Routes>
        <Route path='/home' element={<HomeTab />} />
        <Route path='/help' element={<HelpRequests />} />
        <Route path='/chat' element={<ChatWithFriend />} />
        <Route path='/groups' element={<Cards />} />
        <Route path='/forum' element={<Forum />} />
        <Route path='/search' element={<AdvancedSearch />} />
        <Route path='/dashboard' element={<Dashboard />} />
        <Route path='/startups' element={<Startups />} />
        <Route path='/login' element={<Authentication />} />
        <Route element={<ProtectedRoute fallbackPath='/home' />}>
          {/* <Route path='/' element={isAuth ? <Navigate to='/dashboard' /> : <Navigate to='/login' />} /> */}
          <Route path='/' element={isAuth ? <Navigate to='/home' /> : <Navigate to='/login' />} />
        </Route>
      </Routes>
    </>
  );
}

export default AppWrapper;
