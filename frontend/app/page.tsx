'use client';

import { useState } from 'react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';

export default function Home() {
  const [activeTab, setActiveTab] = useState<'upload' | 'github'>('upload');
  const [files, setFiles] = useState<FileList | null>(null);
  const [repoUrl, setRepoUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');

  const handleScan = async () => {
    setLoading(true);
    setError('');
    setResult(null);

    try {
      let response;
      if (activeTab === 'upload') {
        if (!files || files.length === 0) {
          setError('Please select files to upload.');
          setLoading(false);
          return;
        }
        const formData = new FormData();
        for (let i = 0; i < files.length; i++) {
          formData.append('files', files[i]);
        }
        response = await fetch(`${API_URL}/api/scan/upload`, {
          method: 'POST',
          body: formData,
        });
      } else {
        if (!repoUrl) {
          setError('Please enter a GitHub repository URL.');
          setLoading(false);
          return;
        }
        response = await fetch(`${API_URL}/api/scan/github`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: repoUrl }),
        });
      }

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Scan failed');
      }

      const data = await response.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 p-8 font-sans">
      <div className="max-w-6xl mx-auto">
        <header className="mb-10 text-center">
          <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-500">
            SCA Vulnerability Scanner
          </h1>
          <p className="text-gray-400 mt-2">
            Scan your dependencies and code for security risks
          </p>
        </header>

        {/* Input Section */}
        <div className="bg-gray-800 rounded-xl p-6 shadow-lg border border-gray-700 mb-8">
          <div className="flex space-x-4 mb-6 border-b border-gray-700 pb-2">
            <button
              onClick={() => setActiveTab('upload')}
              className={`pb-2 px-4 text-lg font-medium transition-colors ${activeTab === 'upload'
                ? 'text-blue-400 border-b-2 border-blue-400'
                : 'text-gray-400 hover:text-gray-200'
                }`}
            >
              Upload Config Files
            </button>
            <button
              onClick={() => setActiveTab('github')}
              className={`pb-2 px-4 text-lg font-medium transition-colors ${activeTab === 'github'
                ? 'text-blue-400 border-b-2 border-blue-400'
                : 'text-gray-400 hover:text-gray-200'
                }`}
            >
              GitHub Repository
            </button>
          </div>

          <div className="min-h-[150px] flex flex-col justify-center items-center">
            {activeTab === 'upload' ? (
              <div className="w-full max-w-xl">
                <label className="block mb-2 text-sm font-medium text-gray-300">
                  Select files (package.json, requirements.txt, etc.)
                </label>
                <input
                  type="file"
                  multiple
                  onChange={(e) => setFiles(e.target.files)}
                  className="block w-full text-sm text-gray-400
                    file:mr-4 file:py-2 file:px-4
                    file:rounded-full file:border-0
                    file:text-sm file:font-semibold
                    file:bg-blue-600 file:text-white
                    hover:file:bg-blue-700
                    cursor-pointer bg-gray-700 rounded-lg border border-gray-600"
                />
              </div>
            ) : (
              <div className="w-full max-w-xl">
                <label className="block mb-2 text-sm font-medium text-gray-300">
                  Repository URL
                </label>
                <input
                  type="text"
                  placeholder="https://github.com/username/repo"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  className="w-full p-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-blue-500 outline-none"
                />
              </div>
            )}

            <button
              onClick={handleScan}
              disabled={loading}
              className={`mt-6 px-8 py-3 rounded-lg font-bold text-white transition-all transform hover:scale-105 ${loading
                ? 'bg-gray-600 cursor-not-allowed'
                : 'bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 shadow-lg'
                }`}
            >
              {loading ? 'Scanning...' : 'Start Scan'}
            </button>
          </div>

          {error && (
            <div className="mt-4 p-4 bg-red-900/50 border border-red-700 text-red-200 rounded-lg">
              {error}
            </div>
          )}
        </div>

        {/* Results Section */}
        {result && (
          <div className="space-y-8 animate-fade-in">
            {/* Stats Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {Object.entries(result.stats).map(([severity, count]) => (
                <div
                  key={severity}
                  className={`p-4 rounded-lg border ${severity === 'critical'
                    ? 'bg-red-900/20 border-red-800 text-red-400'
                    : severity === 'high'
                      ? 'bg-orange-900/20 border-orange-800 text-orange-400'
                      : severity === 'medium'
                        ? 'bg-yellow-900/20 border-yellow-800 text-yellow-400'
                        : 'bg-green-900/20 border-green-800 text-green-400'
                    }`}
                >
                  <div className="text-sm uppercase font-bold tracking-wider opacity-80">
                    {severity}
                  </div>
                  <div className="text-3xl font-bold mt-1">{count as number}</div>
                </div>
              ))}
            </div>

            {/* Dependencies Table */}
            <div className="bg-gray-800 rounded-xl shadow-lg border border-gray-700 overflow-hidden">
              <div className="p-4 bg-gray-750 border-b border-gray-700">
                <h2 className="text-xl font-bold text-white">Dependencies</h2>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead className="bg-gray-700 text-gray-300 uppercase text-xs">
                    <tr>
                      <th className="p-4">Package</th>
                      <th className="p-4">Version</th>
                      <th className="p-4">Type</th>
                      <th className="p-4">Risk Score</th>
                      <th className="p-4">Vulnerabilities</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700">
                    {result.dependencies.map((dep: any, idx: number) => (
                      <tr key={idx} className="hover:bg-gray-750/50">
                        <td className="p-4 font-medium text-white">{dep.name}</td>
                        <td className="p-4 text-gray-400">{dep.version}</td>
                        <td className="p-4 text-gray-400">{dep.package_manager}</td>
                        <td className="p-4">
                          <span
                            className={`px-2 py-1 rounded text-xs font-bold ${dep.risk_score >= 8
                              ? 'bg-red-900 text-red-200'
                              : dep.risk_score >= 5
                                ? 'bg-orange-900 text-orange-200'
                                : 'bg-green-900 text-green-200'
                              }`}
                          >
                            {dep.risk_score}
                          </span>
                        </td>
                        <td className="p-4">
                          {dep.vulnerabilities.length > 0 ? (
                            <div className="space-y-2">
                              {dep.vulnerabilities.map((v: any, vIdx: number) => (
                                <div key={vIdx} className="text-sm">
                                  <span
                                    className={`font-bold ${v.severity === 'critical'
                                      ? 'text-red-500'
                                      : v.severity === 'high'
                                        ? 'text-orange-500'
                                        : 'text-yellow-500'
                                      }`}
                                  >
                                    [{v.severity.toUpperCase()}]
                                  </span>{' '}
                                  <span className="text-gray-300">{v.cve_id}</span>
                                  <p className="text-xs text-gray-500 mt-1 truncate max-w-xs">
                                    {v.description}
                                  </p>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <span className="text-green-500 text-sm">Safe</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* SAST Table */}
            {result.code_vulnerabilities && result.code_vulnerabilities.length > 0 && (
              <div className="bg-gray-800 rounded-xl shadow-lg border border-gray-700 overflow-hidden">
                <div className="p-4 bg-gray-750 border-b border-gray-700">
                  <h2 className="text-xl font-bold text-white">Code Security Issues (SAST)</h2>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead className="bg-gray-700 text-gray-300 uppercase text-xs">
                      <tr>
                        <th className="p-4">Severity</th>
                        <th className="p-4">Rule</th>
                        <th className="p-4">Location</th>
                        <th className="p-4">Snippet</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-700">
                      {result.code_vulnerabilities.map((vuln: any, idx: number) => (
                        <tr key={idx} className="hover:bg-gray-750/50">
                          <td className="p-4">
                            <span
                              className={`px-2 py-1 rounded text-xs font-bold ${vuln.severity === 'critical'
                                ? 'bg-red-900 text-red-200'
                                : vuln.severity === 'high'
                                  ? 'bg-orange-900 text-orange-200'
                                  : 'bg-yellow-900 text-yellow-200'
                                }`}
                            >
                              {vuln.severity.toUpperCase()}
                            </span>
                          </td>
                          <td className="p-4 font-medium text-white">{vuln.rule_id}</td>
                          <td className="p-4 text-gray-400">
                            {vuln.file}:{vuln.line}
                          </td>
                          <td className="p-4">
                            <code className="bg-gray-900 px-2 py-1 rounded text-xs text-blue-300 block max-w-md truncate">
                              {vuln.code_snippet}
                            </code>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
